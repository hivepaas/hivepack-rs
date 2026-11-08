//! Extracting tar archives made to attack extractors, as `tests/extract.rs`
//! does for ZIP: names that climb out, the same path twice, symbolic and
//! hard links, devices, the limits, archives cut short, a stream that
//! fails after the archive's end, and an archive that changes between its
//! two readings. Each must stop with its reason and leave nothing outside
//! the destination, and nothing at all when the checks before writing stop
//! it. Then Go's test archives, each extracted or stopped with its reason.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::Cell;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hivepack::extract::{
    Entry, ErrorKind, Limits, LinkOutside, Links, NameError, OnLinksOutside, OnRefused, Options,
    Owners, Progress, Sink, Summary, extract_tar, extract_tar_to, remove_stale,
};

/// The time the test entries have.
const MTIME: u64 = 1_600_000_000;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "hivepack-extract-tar-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// The destination inside it, not created yet.
    fn out(&self) -> PathBuf {
        self.0.join("out")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The paths under `dir`, sorted, with `/` after directories.
fn listing(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let relative = path
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if path.symlink_metadata().unwrap().is_dir() {
                found.push(format!("{relative}/"));
                stack.push(path);
            } else {
                found.push(relative);
            }
        }
    }
    found.sort();
    found
}

/// An entry of a test archive.
enum E<'a> {
    File(&'a [u8], &'a [u8]),
    Mode(&'a [u8], &'a [u8], u32),
    Dir(&'a [u8]),
    Symlink(&'a [u8], &'a [u8]),
    HardLink(&'a [u8], &'a [u8]),
    /// Another type, with no data.
    Type(&'a [u8], u8),
    /// A file whose header says `size`, whatever the data.
    Sized(&'a [u8], &'a [u8], u64),
}

/// A USTAR header block, its checksum written.
fn header(name: &[u8], typeflag: u8, size: u64, mode: u32, linkname: &[u8]) -> Vec<u8> {
    assert!(name.len() <= 100 && linkname.len() <= 100);
    let mut b = vec![0u8; 512];
    b[..name.len()].copy_from_slice(name);
    b[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
    b[108..116].copy_from_slice(b"0001750\0");
    b[116..124].copy_from_slice(b"0001750\0");
    b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    b[136..148].copy_from_slice(format!("{MTIME:011o}\0").as_bytes());
    b[156] = typeflag;
    b[157..157 + linkname.len()].copy_from_slice(linkname);
    b[257..265].copy_from_slice(b"ustar\x0000");
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&c| u32::from(c)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    b
}

/// A tar archive of `entries`, ended by two zero blocks.
fn tar(entries: &[E<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut add = |h: Vec<u8>, data: &[u8]| {
        out.extend(h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    };
    for entry in entries {
        match *entry {
            E::File(name, data) => add(header(name, b'0', data.len() as u64, 0o644, b""), data),
            E::Mode(name, data, mode) => {
                add(header(name, b'0', data.len() as u64, mode, b""), data)
            }
            E::Dir(name) => add(header(name, b'5', 0, 0o755, b""), b""),
            E::Symlink(name, target) => add(header(name, b'2', 0, 0o777, target), b""),
            E::HardLink(name, target) => add(header(name, b'1', 0, 0o644, target), b""),
            E::Type(name, t) => add(header(name, t, 0, 0o644, b""), b""),
            E::Sized(name, data, size) => add(header(name, b'0', size, 0o644, b""), data),
        }
    }
    out.extend([0u8; 1024]);
    out
}

fn extract(
    data: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    extract_tar(|| Ok(Cursor::new(data)), out, options)
}

fn options(change: impl FnOnce(&mut Options)) -> Options {
    let mut options = portable();
    change(&mut options);
    options
}

#[test]
fn extracts_files_directories_and_dot_slash_names() {
    let s = Scratch::new();
    let data = tar(&[
        E::Dir(b"./"),
        E::Dir(b"./a/"),
        E::File(b"./a/one.txt", b"one"),
        E::File(b"two.txt", b"two two"),
        E::Mode(b"run.sh", b"#!/bin/sh\n", 0o4777),
        E::Type(b"globals", b'g'),
    ]);
    let summary = extract(&data, &s.out(), &portable()).unwrap();
    assert_eq!(
        (summary.files, summary.directories, summary.bytes),
        (3, 1, 20)
    );
    assert_eq!(listing(&s.out()), ["a/", "a/one.txt", "run.sh", "two.txt"]);
    assert_eq!(std::fs::read(s.out().join("a/one.txt")).unwrap(), b"one");
    let mtime = std::fs::metadata(s.out().join("two.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        mtime,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(MTIME)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(s.out().join("run.sh"))
            .unwrap()
            .permissions()
            .mode();
        // No setuid, nothing writable by group or others.
        assert_eq!(mode & 0o7777, 0o755);
    }
}

#[test]
fn refused_names_write_nothing() {
    let cases: [(&[u8], NameError); 7] = [
        (b"../escape.txt", NameError::Dot),
        (b"a/../../escape.txt", NameError::Dot),
        (b"/etc/passwd", NameError::Absolute),
        (b"a\\b.txt", NameError::Backslash),
        (b"C:x.txt", NameError::Colon),
        (b"aux.txt", NameError::Device),
        (b"bell\x07.txt", NameError::Control),
    ];
    for (name, reason) in cases {
        let s = Scratch::new();
        let data = tar(&[E::File(b"first.txt", b"x"), E::File(name, b"y")]);
        let e = extract(&data, &s.out(), &portable()).unwrap_err();
        assert!(
            matches!(e.kind, ErrorKind::Name(r) if r == reason),
            "{name:?}: {e}"
        );
        assert_eq!(e.index, Some(1));
        // Checked before anything is written: not even the destination.
        assert!(!s.out().exists(), "{name:?}");
        assert_eq!(listing(s.path()), Vec::<String>::new());
    }
    // Not UTF-8.
    let s = Scratch::new();
    let e = extract(
        &tar(&[E::File(b"caf\xe9.txt", b"x")]),
        &s.out(),
        &portable(),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Name(NameError::NotUtf8)), "{e}");
}

#[test]
fn the_same_path_twice_is_refused() {
    for second in [&b"README.txt"[..], b"readme.TXT", b"./readme.txt"] {
        let s = Scratch::new();
        let data = tar(&[E::File(b"readme.txt", b"a"), E::File(second, b"b")]);
        let e = extract(&data, &s.out(), &portable()).unwrap_err();
        assert!(
            matches!(e.kind, ErrorKind::Duplicate { first: 0 }),
            "{second:?}: {e}"
        );
        assert!(!s.out().exists());
    }
    // A file, then a directory of its name.
    let s = Scratch::new();
    let data = tar(&[E::File(b"x", b"a"), E::File(b"x/y", b"b")]);
    assert!(matches!(
        extract(&data, &s.out(), &portable()).unwrap_err().kind,
        ErrorKind::Duplicate { .. }
    ));
}

#[test]
fn symbolic_links_follow_the_options() {
    let data = tar(&[
        E::Dir(b"d/"),
        E::File(b"d/f", b"data"),
        E::Symlink(b"l", b"d/f"),
    ]);
    // Refused by default.
    let s = Scratch::new();
    let e = extract(&data, &s.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Link), "{e}");
    assert!(!s.out().exists());
    // As a file holding the target.
    let s = Scratch::new();
    extract(&data, &s.out(), &options(|o| o.links = Links::AsFile)).unwrap();
    assert_eq!(std::fs::read(s.out().join("l")).unwrap(), b"d/f");
    // Created, inside.
    #[cfg(unix)]
    {
        let s = Scratch::new();
        let summary = extract(&data, &s.out(), &options(|o| o.links = Links::Inside)).unwrap();
        assert_eq!(summary.links, 1);
        assert_eq!(
            std::fs::read_link(s.out().join("l")).unwrap(),
            Path::new("d/f")
        );
        assert_eq!(std::fs::read(s.out().join("l")).unwrap(), b"data");
    }
    // Climbing out, absolute, or through another link: refused before
    // anything is written.
    let cases: [(&[u8], &[u8]); 3] = [
        (b"l", b"../../etc/passwd"),
        (b"l", b"/etc/passwd"),
        (b"d/l2", b"../l/x"),
    ];
    for (name, target) in cases {
        let s = Scratch::new();
        let data = tar(&[
            E::Dir(b"d/"),
            E::Symlink(b"l", b"d"),
            E::Symlink(name, target),
        ]);
        let e = extract(&data, &s.out(), &options(|o| o.links = Links::Inside)).unwrap_err();
        assert!(
            matches!(
                e.kind,
                ErrorKind::LinkTarget(_)
                    | ErrorKind::LinkChain { .. }
                    | ErrorKind::Duplicate { .. }
            ),
            "{target:?}: {e}"
        );
        assert!(!s.out().exists());
    }
}

/// With `Links::Any`, symbolic links anywhere are created as the archive has
/// them; with `Links::Inside`, those that lead outside are asked about once.
#[cfg(unix)]
#[test]
fn symbolic_links_anywhere_are_created_or_asked_about() {
    let data = tar(&[
        E::Dir(b"d/"),
        E::File(b"d/f", b"data"),
        E::Symlink(b"l", b"d"),
        E::Symlink(b"abs", b"/etc/passwd"),
        E::Symlink(b"up", b"../../outside"),
        E::Symlink(b"d/through", b"../l/f"),
        E::Symlink(b"in", b"d/f"),
    ]);
    let s = Scratch::new();
    let summary = extract(&data, &s.out(), &options(|o| o.links = Links::Any)).unwrap();
    assert_eq!((summary.files, summary.links), (1, 5));
    for (link, target) in [
        ("abs", "/etc/passwd"),
        ("up", "../../outside"),
        ("d/through", "../l/f"),
    ] {
        assert_eq!(
            std::fs::read_link(s.out().join(link)).unwrap(),
            Path::new(target)
        );
    }
    assert_eq!(std::fs::read(s.out().join("d/through")).unwrap(), b"data");

    // Asked once, with the three that lead outside, in the archive's order.
    let asked = Arc::new(Mutex::new(Vec::new()));
    let ask = |answer| {
        let told = Arc::clone(&asked);
        options(move |o| {
            o.links = Links::Inside;
            o.on_links_outside = Some(Arc::new(move |links: &[LinkOutside]| {
                told.lock().unwrap().push(
                    links
                        .iter()
                        .map(|l| (l.target.clone(), format!("{:?}", l.error.kind)))
                        .collect::<Vec<_>>(),
                );
                answer
            }));
        })
    };
    let expected = vec![
        (
            "/etc/passwd".to_string(),
            "LinkTarget(Absolute)".to_string(),
        ),
        ("../../outside".to_string(), "LinkTarget(Dot)".to_string()),
        ("../l/f".to_string(), "LinkChain { other: 2 }".to_string()),
    ];
    let s = Scratch::new();
    let e = extract(&data, &s.out(), &ask(OnLinksOutside::Stop)).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::LinkTarget(_)), "{e}");
    assert!(!s.out().exists());
    let s = Scratch::new();
    let summary = extract(&data, &s.out(), &ask(OnLinksOutside::Skip)).unwrap();
    assert_eq!((summary.links, summary.skipped.len()), (2, 3));
    let s = Scratch::new();
    let summary = extract(&data, &s.out(), &ask(OnLinksOutside::Create)).unwrap();
    assert_eq!((summary.links, summary.skipped.len()), (5, 0));
    assert_eq!(*asked.lock().unwrap(), vec![expected; 3]);

    // A file under a link that leads out is the link's path, with Any too.
    let s = Scratch::new();
    let data = tar(&[E::Symlink(b"out", b"/tmp"), E::File(b"out/x", b"through")]);
    let e = extract(&data, &s.out(), &options(|o| o.links = Links::Any)).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Duplicate { .. }), "{e}");
    assert!(!s.out().exists());
}

#[test]
fn hard_links_name_files_extracted_before_them() {
    let data = tar(&[
        E::File(b"a.txt", b"shared"),
        E::HardLink(b"b.txt", b"./a.txt"),
    ]);
    let s = Scratch::new();
    let summary = extract(&data, &s.out(), &portable()).unwrap();
    assert_eq!(summary.files, 2);
    assert_eq!(std::fs::read(s.out().join("b.txt")).unwrap(), b"shared");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = std::fs::metadata(s.out().join("a.txt")).unwrap();
        let b = std::fs::metadata(s.out().join("b.txt")).unwrap();
        assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()));
    }
    // As a copy with Links::AsFile.
    let s = Scratch::new();
    let summary = extract(&data, &s.out(), &options(|o| o.links = Links::AsFile)).unwrap();
    assert_eq!(summary.bytes, 12);
    assert_eq!(std::fs::read(s.out().join("b.txt")).unwrap(), b"shared");

    // To nothing, to a later file, outside, or to a directory: refused
    // before anything is written.
    let cases: [Vec<u8>; 4] = [
        tar(&[
            E::File(b"a.txt", b"x"),
            E::HardLink(b"b.txt", b"missing.txt"),
        ]),
        tar(&[E::HardLink(b"b.txt", b"a.txt"), E::File(b"a.txt", b"x")]),
        tar(&[E::File(b"a.txt", b"x"), E::HardLink(b"b.txt", b"../a.txt")]),
        tar(&[E::Dir(b"d/"), E::HardLink(b"b", b"d")]),
    ];
    for data in cases {
        let s = Scratch::new();
        let e = extract(&data, &s.out(), &portable()).unwrap_err();
        assert!(
            matches!(e.kind, ErrorKind::HardLinkTarget | ErrorKind::LinkTarget(_)),
            "{e}"
        );
        assert!(!s.out().exists());
    }
}

#[test]
fn devices_and_fifos_are_not_created() {
    for t in *b"346" {
        let s = Scratch::new();
        let data = tar(&[E::File(b"a.txt", b"x"), E::Type(b"dev", t)]);
        let e = extract(&data, &s.out(), &portable()).unwrap_err();
        assert!(matches!(e.kind, ErrorKind::Special), "{e}");
        assert!(!s.out().exists());
        // Left out with Skip.
        let s = Scratch::new();
        let summary = extract(
            &data,
            &s.out(),
            &options(|o| o.on_refused = OnRefused::Skip),
        )
        .unwrap();
        assert_eq!(summary.skipped.len(), 1);
        assert_eq!(listing(&s.out()), ["a.txt"]);
    }
}

/// An old GNU sparse entry of `real` bytes, whose `data` lies at each `offset`,
/// and the archive around it.
fn sparse(real: u64, offset: &[u64], data: &[u8]) -> Vec<u8> {
    let mut b = header(
        b"big",
        b'S',
        offset.len() as u64 * data.len() as u64,
        0o644,
        b"",
    );
    for (i, at) in offset.iter().enumerate() {
        let entry = 386 + i * 24;
        b[entry..entry + 12].copy_from_slice(format!("{at:011o}\0").as_bytes());
        let length = format!("{:011o}\0", data.len());
        b[entry + 12..entry + 24].copy_from_slice(length.as_bytes());
    }
    b[483..495].copy_from_slice(format!("{real:011o}\0").as_bytes());
    b[257..265].copy_from_slice(b"ustar  \0");
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&c| u32::from(c)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut out = b;
    for _ in offset {
        out.extend_from_slice(data);
    }
    out.resize(out.len().div_ceil(512) * 512 + 1024, 0);
    out
}

/// What the file holds, its bytes at `offset` being `data`, and zeros otherwise.
fn check_sparse(path: &Path, real: u64, offset: &[u64], data: &[u8]) {
    let got = std::fs::read(path).unwrap();
    assert_eq!(got.len() as u64, real);
    let mut want = vec![0; real as usize];
    for &at in offset {
        want[at as usize..at as usize + data.len()].copy_from_slice(data);
    }
    assert!(got == want);
}

#[test]
fn sparse_files_keep_their_holes() {
    const REAL: u64 = 32 << 20;
    let data = vec![b'x'; 4096];
    let scratch = Scratch::new();
    let out = scratch.out();
    let archive = sparse(REAL, &[0, REAL - 4096], &data);
    let summary = extract(&archive, &out, &portable()).unwrap();
    // A hole counts as what the file comes to.
    assert_eq!(summary.bytes, REAL);
    check_sparse(&out.join("big"), REAL, &[0, REAL - 4096], &data);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let blocks = std::fs::metadata(out.join("big")).unwrap().blocks();
        assert!(blocks * 512 < REAL / 2, "{blocks} blocks");
    }
}

#[test]
fn sparse_files_that_end_in_a_hole_have_their_length() {
    const REAL: u64 = 1 << 20;
    let data = vec![b'x'; 512];
    let scratch = Scratch::new();
    let out = scratch.out();
    let archive = sparse(REAL, &[4096], &data);
    extract(&archive, &out, &portable()).unwrap();
    check_sparse(&out.join("big"), REAL, &[4096], &data);
}

#[test]
fn a_sparse_file_replacing_another_leaves_nothing_of_it() {
    const REAL: u64 = 1 << 20;
    let data = vec![b'x'; 512];
    let scratch = Scratch::new();
    let out = scratch.out();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("big"), vec![b'o'; 2 << 20]).unwrap();
    let archive = sparse(REAL, &[4096], &data);
    extract(&archive, &out, &options(|o| o.overwrite = true)).unwrap();
    check_sparse(&out.join("big"), REAL, &[4096], &data);
}

#[test]
fn holes_count_against_the_limits() {
    const REAL: u64 = 1 << 20;
    let data = vec![b'x'; 512];
    let scratch = Scratch::new();
    let out = scratch.out();
    let archive = sparse(REAL, &[4096], &data);
    let limited = options(|o| o.limits.max_entry_size = REAL - 1);
    let error = extract(&archive, &out, &limited).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::EntryTooLarge), "{error}");
}

#[test]
fn limits_stop_archive_bombs_before_writing() {
    let limits = |change: fn(&mut Limits)| {
        let mut limits = Limits::default();
        change(&mut limits);
        options(|o| o.limits = limits)
    };
    let data = tar(&[E::File(b"a", &[0; 3000]), E::File(b"b", &[0; 3000])]);
    type Case = (Options, fn(&ErrorKind) -> bool);
    let cases: [Case; 3] = [
        (limits(|l| l.max_entries = 1), |k| {
            matches!(k, ErrorKind::TooManyEntries)
        }),
        (limits(|l| l.max_entry_size = 2999), |k| {
            matches!(k, ErrorKind::EntryTooLarge)
        }),
        (limits(|l| l.max_total_size = 5999), |k| {
            matches!(k, ErrorKind::TotalTooLarge)
        }),
    ];
    for (options, expect) in cases {
        let s = Scratch::new();
        let e = extract(&data, &s.out(), &options).unwrap_err();
        assert!(expect(&e.kind), "{e}");
        assert!(!s.out().exists());
    }
}

#[test]
fn an_archive_cut_short_leaves_no_file_cut_off() {
    let mut data = tar(&[E::File(b"a.txt", b"whole"), E::File(b"b.txt", &[7; 5000])]);
    // Cut in the middle of b.txt's data: the first reading reads past it,
    // so it already fails there.
    data.truncate(512 + 512 + 512 + 2000);
    let s = Scratch::new();
    let e = extract(&data, &s.out(), &portable()).unwrap_err();
    assert!(
        matches!(e.kind, ErrorKind::Tar(hivepack::tar::Error::UnexpectedEof)),
        "{e}"
    );
    assert!(!s.out().exists());

    // A header that says more data than the archive holds before its end.
    let data = tar(&[
        E::File(b"a.txt", b"whole"),
        E::Sized(b"b.txt", b"short", 100_000),
    ]);
    let s = Scratch::new();
    let e = extract(&data, &s.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Tar(_)), "{e}");
    assert!(!s.out().exists());
}

/// A stream that fails once `data` is read, as a compressor fails its
/// check at its end.
struct FailsAtTheEnd(Cursor<Vec<u8>>);

impl std::io::Read for FailsAtTheEnd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(buf)? {
            0 => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the check at the end failed",
            )),
            n => Ok(n),
        }
    }
}

#[test]
fn the_stream_is_read_past_the_archive_to_its_end() {
    // What follows the archive's end is read, so that a check at the end
    // of the stream fails before anything is written.
    let mut data = tar(&[E::File(b"a.txt", b"whole")]);
    data.extend([0; 10_000]);
    let s = Scratch::new();
    let e = extract_tar(
        || Ok(FailsAtTheEnd(Cursor::new(data.clone()))),
        &s.out(),
        &portable(),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Io(_)), "{e}");
    assert!(!s.out().exists());

    // Into a folder the archive is read once: the file was written, into
    // the private folder, before the check failed, and nothing is left of it.
    let s = Scratch::new();
    std::fs::create_dir(s.out()).unwrap();
    let e = extract_tar(
        || Ok(FailsAtTheEnd(Cursor::new(data.clone()))),
        &s.out(),
        &portable(),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Io(_)), "{e}");
    assert!(listing(&s.out()).is_empty(), "{:?}", listing(&s.out()));

    // What follows is limited by the limit on all that is written, or by
    // 1 MiB, the largest record tar pads to, if that is less.
    let limited = options(|o| o.limits.max_total_size = 5_000);
    let mut padded = tar(&[E::File(b"a.txt", b"whole")]);
    padded.resize(padded.len() + (1 << 20), 0);
    let s = Scratch::new();
    assert_eq!(extract(&padded, &s.out(), &limited).unwrap().files, 1);
    padded.push(0);
    let s = Scratch::new();
    let e = extract(&padded, &s.out(), &limited).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::TotalTooLarge), "{e}");
    assert!(!s.out().exists());
}

#[test]
fn into_a_folder_the_archive_is_read_once() {
    let data = tar(&[E::File(b"a.txt", b"one"), E::File(b"b.txt", b"two")]);
    let s = Scratch::new();
    let calls = Cell::new(0);
    let summary = extract_tar(
        || {
            calls.set(calls.get() + 1);
            Ok(Cursor::new(data.clone()))
        },
        &s.out(),
        &portable(),
    )
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(summary.files, 2);
    // Nothing else is left: the private folder is gone.
    assert_eq!(listing(&s.out()), ["a.txt", "b.txt"]);
}

/// Read twice into a sink, an archive that changes between the readings stops.
#[test]
fn an_archive_that_changes_between_readings_stops() {
    let first = tar(&[E::File(b"a.txt", b"one"), E::File(b"b.txt", b"two")]);
    let cases = [
        // Another name for the second entry.
        tar(&[E::File(b"a.txt", b"one"), E::File(b"evil.txt", b"two")]),
        // Another size.
        tar(&[E::File(b"a.txt", b"one"), E::File(b"b.txt", b"three")]),
        // An entry more, and one fewer.
        tar(&[
            E::File(b"a.txt", b"one"),
            E::File(b"b.txt", b"two"),
            E::File(b"c.txt", b"x"),
        ]),
        tar(&[E::File(b"a.txt", b"one")]),
    ];
    for second in cases {
        let calls = Cell::new(0);
        let mut names = Names::default();
        let result = extract_tar_to(
            || {
                calls.set(calls.get() + 1);
                Ok(Cursor::new(if calls.get() == 1 {
                    first.clone()
                } else {
                    second.clone()
                }))
            },
            &mut names,
            &portable(),
        );
        let e = result.unwrap_err();
        assert!(matches!(e.kind, ErrorKind::Changed), "{e}");
        assert_eq!(calls.get(), 2);
        // Only what the first reading checked was given.
        for name in &names.0 {
            assert!(["a.txt", "b.txt"].contains(&name.as_str()), "{name}");
        }
    }
}

#[test]
fn progress_counts_links_written_as_files() {
    // With Links::AsFile, a symbolic link's target and a hard link's copy
    // are written, which tar's sizes do not count: the totals must. The
    // `extract_tar` fuzz target found them missing.
    let data = tar(&[
        E::File(b"a.txt", b"shared"),
        E::Symlink(b"s", b"a.txt"),
        E::HardLink(b"h", b"a.txt"),
        E::HardLink(b"h2", b"h"),
    ]);
    let seen: Arc<Mutex<Vec<Progress>>> = Arc::default();
    let record = Arc::clone(&seen);
    let s = Scratch::new();
    let summary = extract(
        &data,
        &s.out(),
        &options(|o| {
            o.links = Links::AsFile;
            o.progress = Some(Arc::new(move |p: &Progress| {
                record.lock().unwrap().push(*p)
            }));
        }),
    )
    .unwrap();
    // "shared", "a.txt" and two copies of "shared".
    assert_eq!(summary.bytes, 6 + 5 + 6 + 6);
    let seen = seen.lock().unwrap();
    let last = seen.last().unwrap();
    assert_eq!((last.bytes, last.total_bytes), (23, 23));
    assert_eq!((last.entries, last.total_entries), (4, 4));
    // The totals are known once the archive is read: none passes them
    // after.
    let known = seen.iter().position(|p| p.total_bytes > 0).unwrap();
    assert!(
        seen[known..]
            .iter()
            .all(|p| p.bytes <= p.total_bytes && p.entries <= p.total_entries)
    );
}

#[test]
fn a_time_limit_of_zero_stops_before_writing() {
    let s = Scratch::new();
    let data = tar(&[E::File(b"a.txt", b"x")]);
    let e = extract(
        &data,
        &s.out(),
        &options(|o| o.time_limit = Some(std::time::Duration::ZERO)),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::TimeLimit), "{e}");
}

#[test]
fn nothing_is_overwritten_unless_asked() {
    let s = Scratch::new();
    std::fs::create_dir_all(s.out()).unwrap();
    std::fs::write(s.out().join("a.txt"), b"old").unwrap();
    let data = tar(&[E::File(b"a.txt", b"new")]);
    let e = extract(&data, &s.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Exists), "{e}");
    assert_eq!(std::fs::read(s.out().join("a.txt")).unwrap(), b"old");
    extract(&data, &s.out(), &options(|o| o.overwrite = true)).unwrap();
    assert_eq!(std::fs::read(s.out().join("a.txt")).unwrap(), b"new");
}

/// Go's test archives (`testdata/go-tar`), the plain ones.
fn go_archives() -> Vec<(String, Vec<u8>)> {
    let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/go-tar");
    let mut archives: Vec<(String, Vec<u8>)> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "tar"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();
    archives.sort();
    archives
}

#[test]
fn go_test_archives_extract_or_stop_with_their_reason() {
    let mut outcomes = std::collections::BTreeMap::new();
    for (name, data) in go_archives() {
        for skip in [false, true] {
            let s = Scratch::new();
            // Beside the destination: must stay as it is.
            std::fs::write(s.path().join("beside.txt"), b"beside").unwrap();
            let opts = options(|o| {
                if skip {
                    o.on_refused = OnRefused::Skip;
                }
            });
            let outcome = match extract(&data, &s.out(), &opts) {
                Ok(summary) => format!("ok {} files", summary.files),
                // Not the name, whose bytes are not UTF-8.
                Err(e) if matches!(e.kind, ErrorKind::Name(NameError::NotUtf8)) => {
                    format!("entry {}: {}", e.index.unwrap(), e.kind)
                }
                Err(e) => format!("{e}"),
            };
            assert_eq!(
                std::fs::read(s.path().join("beside.txt")).unwrap(),
                b"beside"
            );
            for path in listing(s.path()) {
                assert!(
                    path == "beside.txt" || path.starts_with("out/") || path == "out/",
                    "{name}: {path}"
                );
            }
            outcomes.insert(
                format!("{name} {}", if skip { "skip" } else { "stop" }),
                outcome,
            );
        }
    }
    // Each as it went when this test was written, so that a change shows:
    // the links and the FIFO refused, or left out with Skip; the names not
    // UTF-8; the archives Go's reader refuses; and writer-big.tar, whose
    // 16 GiB file is cut short, which the first reading finds.
    let expected: &[(&str, &str)] = &[
        ("file-and-dir.tar skip", "ok 1 files"),
        ("file-and-dir.tar stop", "ok 1 files"),
        ("gnu-incremental.tar skip", "ok 2 files"),
        ("gnu-incremental.tar stop", "ok 2 files"),
        ("gnu-long-nul.tar skip", "ok 1 files"),
        ("gnu-long-nul.tar stop", "ok 1 files"),
        ("gnu-multi-hdrs.tar skip", "ok 0 files"),
        (
            "gnu-multi-hdrs.tar stop",
            "entry 0 (GNU2/GNU2/long-path-name): link",
        ),
        ("gnu-nil-sparse-data.tar skip", "ok 1 files"),
        ("gnu-nil-sparse-data.tar stop", "ok 1 files"),
        ("gnu-nil-sparse-hole.tar skip", "ok 1 files"),
        ("gnu-nil-sparse-hole.tar stop", "ok 1 files"),
        ("gnu-not-utf8.tar skip", "ok 0 files"),
        ("gnu-not-utf8.tar stop", "entry 0: name refused: not UTF-8"),
        ("gnu-utf8.tar skip", "ok 1 files"),
        ("gnu-utf8.tar stop", "ok 1 files"),
        ("gnu.tar skip", "ok 2 files"),
        ("gnu.tar stop", "ok 2 files"),
        ("hardlink.tar skip", "ok 2 files"),
        ("hardlink.tar stop", "ok 2 files"),
        ("hdr-only.tar skip", "ok 2 files"),
        ("hdr-only.tar stop", "entry 1 (fifo): device or FIFO"),
        ("invalid-go17.tar skip", "ok 1 files"),
        ("invalid-go17.tar stop", "ok 1 files"),
        (
            "issue10968.tar skip",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "issue10968.tar stop",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "issue11169.tar skip",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "issue11169.tar stop",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "issue12435.tar skip",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "issue12435.tar stop",
            "archive: archive/tar: invalid tar header",
        ),
        ("nil-uid.tar skip", "ok 1 files"),
        ("nil-uid.tar stop", "ok 1 files"),
        (
            "pax-bad-hdr-file.tar skip",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "pax-bad-hdr-file.tar stop",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "pax-bad-mtime-file.tar skip",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "pax-bad-mtime-file.tar stop",
            "archive: archive/tar: invalid tar header",
        ),
        ("pax-global-records.tar skip", "ok 4 files"),
        ("pax-global-records.tar stop", "ok 4 files"),
        ("pax-multi-hdrs.tar skip", "ok 0 files"),
        ("pax-multi-hdrs.tar stop", "entry 0 (bar): link"),
        ("pax-nil-sparse-data.tar skip", "ok 1 files"),
        ("pax-nil-sparse-data.tar stop", "ok 1 files"),
        ("pax-nil-sparse-hole.tar skip", "ok 1 files"),
        ("pax-nil-sparse-hole.tar stop", "ok 1 files"),
        (
            "pax-nul-path.tar skip",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "pax-nul-path.tar stop",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "pax-nul-xattrs.tar skip",
            "archive: archive/tar: invalid tar header",
        ),
        (
            "pax-nul-xattrs.tar stop",
            "archive: archive/tar: invalid tar header",
        ),
        ("pax-path-hdr.tar skip", "ok 0 files"),
        ("pax-path-hdr.tar stop", "ok 0 files"),
        ("pax-pos-size-file.tar skip", "ok 1 files"),
        ("pax-pos-size-file.tar stop", "ok 1 files"),
        ("pax-records.tar skip", "ok 1 files"),
        ("pax-records.tar stop", "ok 1 files"),
        ("pax.tar skip", "ok 1 files"),
        ("pax.tar stop", "entry 1 (a/b): link"),
        ("sparse-formats.tar skip", "ok 5 files"),
        ("sparse-formats.tar stop", "ok 5 files"),
        ("star.tar skip", "ok 2 files"),
        ("star.tar stop", "ok 2 files"),
        ("trailing-slash.tar skip", "ok 0 files"),
        ("trailing-slash.tar stop", "ok 0 files"),
        ("ustar-file-devs.tar skip", "ok 1 files"),
        ("ustar-file-devs.tar stop", "ok 1 files"),
        ("ustar-file-reg.tar skip", "ok 1 files"),
        ("ustar-file-reg.tar stop", "ok 1 files"),
        ("ustar.tar skip", "ok 1 files"),
        ("ustar.tar stop", "ok 1 files"),
        ("v7.tar skip", "ok 2 files"),
        ("v7.tar stop", "ok 2 files"),
        ("writer-big.tar skip", "archive: unexpected EOF"),
        ("writer-big.tar stop", "archive: unexpected EOF"),
        ("writer.tar skip", "ok 2 files"),
        ("writer.tar stop", "entry 2 (link.txt): link"),
        ("xattrs.tar skip", "ok 2 files"),
        ("xattrs.tar stop", "ok 2 files"),
    ];
    let expected: std::collections::BTreeMap<String, String> = expected
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert_eq!(outcomes, expected);
}

/// A tar archive of symbolic links and directories with names of any length,
/// in PAX records as Python's tarfile writes them.
fn long_tar(entries: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut writer = hivepack::tar::Writer::new(Vec::new());
    for (typeflag, name, linkname) in entries {
        let header = hivepack::tar::Header {
            typeflag: *typeflag,
            name: name.clone(),
            linkname: linkname.clone(),
            mode: 0o755,
            ..Default::default()
        };
        writer.write_header(&header).unwrap();
    }
    writer.close().unwrap();
    writer.into_inner()
}

/// Python's CVE-2025-4517, as its finders built it: links to directories of
/// long names, past `PATH_MAX`, where `os.path.realpath` gave up and the
/// filter saw a path inside, then a link that climbs through them and out, and
/// a file through that. Nothing here asks the system where a path leads.
#[cfg(unix)]
#[test]
fn cve_2025_4517_a_climb_through_links_past_path_max() {
    let long = vec![b'd'; 247];
    let mut entries = Vec::new();
    let mut path = Vec::<u8>::new();
    for step in b'a'..=b'p' {
        let mut dir = path.clone();
        dir.extend_from_slice(&long);
        entries.push((b'5', dir, Vec::new()));
        let mut link = path.clone();
        link.push(step);
        entries.push((b'2', link.clone(), long.clone()));
        path = link;
        path.push(b'/');
    }
    let mut up = path.clone();
    up.extend_from_slice(&[b'l'; 254]);
    entries.push((b'2', up.clone(), b"../".repeat(16)));
    let mut out = up;
    out.extend_from_slice(b"/../../../../../../../secret");
    entries.push((b'2', b"escape".to_vec(), out));
    entries.push((b'1', b"flag".to_vec(), b"escape".to_vec()));
    let data = long_tar(&entries);

    let inside = options(|o| o.links = Links::Inside);
    let s = Scratch::new();
    std::fs::write(s.path().join("secret"), b"outside").unwrap();
    // A path under a link is the same path as the link.
    let error = extract(&data, &s.out(), &inside).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Duplicate { first: 1 }),
        "{error}"
    );
    assert!(!s.out().exists());

    // Going on past what is refused: no link there leads out.
    let skipping = options(|o| {
        o.links = Links::Inside;
        o.on_refused = OnRefused::Skip;
    });
    let s = Scratch::new();
    std::fs::write(s.path().join("secret"), b"outside").unwrap();
    let summary = extract(&data, &s.out(), &skipping).unwrap();
    let last = summary.skipped.last().unwrap();
    assert!(matches!(last.kind, ErrorKind::HardLinkTarget), "{last:?}");
    let escape = &summary.skipped[summary.skipped.len() - 2];
    assert!(
        matches!(escape.kind, ErrorKind::LinkChain { other: 1 }),
        "{escape:?}"
    );
    assert!(std::fs::read(s.out().join("escape")).is_err());
    assert!(std::fs::read(s.out().join("flag")).is_err());
    assert_eq!(std::fs::read(s.path().join("secret")).unwrap(), b"outside");
}

/// Python's CVE-2025-4138 and CVE-2025-4330: a link's target checked by its
/// text, which stays inside, where the system goes through another link of the
/// archive and out. `a/up/../secret` reads as `a/secret`.
#[cfg(unix)]
#[test]
fn cve_2025_4138_a_target_inside_by_its_text_only() {
    let data = tar(&[
        E::Dir(b"a"),
        E::Symlink(b"a/up", b".."),
        E::Symlink(b"esc", b"a/up/../secret"),
    ]);
    let s = Scratch::new();
    std::fs::write(s.path().join("secret"), b"outside").unwrap();
    let inside = options(|o| o.links = Links::Inside);
    let error = extract(&data, &s.out(), &inside).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::LinkChain { other: 1 }),
        "{error}"
    );
    assert!(!s.out().exists());

    let skipping = options(|o| {
        o.links = Links::Inside;
        o.on_refused = OnRefused::Skip;
    });
    let summary = extract(&data, &s.out(), &skipping).unwrap();
    assert_eq!(summary.skipped.len(), 1);
    assert!(std::fs::symlink_metadata(s.out().join("esc")).is_err());
    assert!(std::fs::read(s.out().join("a/up")).is_err());
}

/// Python's CVE-2024-12718: a file's metadata set outside, through a link to a
/// file there, then an entry of the link's name with its mode and time.
#[cfg(unix)]
#[test]
fn cve_2024_12718_metadata_through_a_link() {
    use std::os::unix::fs::PermissionsExt;
    let data = tar(&[E::Symlink(b"l", b"../secret"), E::Mode(b"l", b"", 0o777)]);
    let s = Scratch::new();
    let secret = s.path().join("secret");
    std::fs::write(&secret, b"outside").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::metadata(&secret).unwrap().modified().unwrap();
    for links in [Links::Refuse, Links::Inside, Links::AsFile] {
        let chosen = options(|o| o.links = links);
        assert!(extract(&data, &s.out(), &chosen).is_err(), "{links:?}");
        assert!(!s.out().exists(), "{links:?}");
    }
    let meta = std::fs::metadata(&secret).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(meta.modified().unwrap(), before);
}

/// Python's CVE-2025-4435: with `errorlevel=0` the members a filter refused
/// were extracted all the same, and those after one could depend on it.
/// Here one left out stays out, and what comes after is under a real directory.
#[test]
fn cve_2025_4435_what_is_skipped_stays_out() {
    let data = tar(&[
        E::Symlink(b"l", b"../outside"),
        E::File(b"after.txt", b"after"),
        E::File(b"../climbs.txt", b"out"),
        E::HardLink(b"hard", b"l"),
    ]);
    let s = Scratch::new();
    let inside = options(|o| {
        o.links = Links::Inside;
        o.on_refused = OnRefused::Skip;
    });
    let summary = extract(&data, &s.out(), &inside).unwrap();
    assert_eq!(summary.skipped.len(), 3);
    assert_eq!(std::fs::read(s.out().join("after.txt")).unwrap(), b"after");
    assert!(std::fs::symlink_metadata(s.out().join("l")).is_err());
    assert!(std::fs::symlink_metadata(s.out().join("hard")).is_err());
    assert!(!s.path().join("climbs.txt").exists());
    assert!(!s.path().join("outside").exists());
}

/// The options of these tests: names checked by every system's rules, as Windows
/// and a case-insensitive file system have them, wherever the tests run.
fn portable() -> hivepack::extract::Options {
    let mut options = hivepack::extract::Options::default();
    options.name_rules = hivepack::extract::NameRules::Portable;
    options
}

/// The extended attribute `name` of the file at `path`, if it has one.
#[cfg(target_os = "linux")]
fn xattr_of(path: &Path, name: &str) -> Option<Vec<u8>> {
    let mut value = vec![0u8; 256];
    let n = rustix::fs::lgetxattr(path, name, &mut value[..]).ok()?;
    value.truncate(n);
    Some(value)
}

/// A tar archive kept for a backup: a folder and a file, each with an owner and
/// group, and extended attributes, `security.capability` among the file's.
#[cfg(target_os = "linux")]
fn kept_for_a_backup(uid: u32, gid: u32) -> Vec<u8> {
    kept_for_a_backup_named(uid, gid, "someone", "")
}

/// [`kept_for_a_backup`], its entries' owner and group named `user` and `group`.
#[cfg(target_os = "linux")]
fn kept_for_a_backup_named(uid: u32, gid: u32, user: &str, group: &str) -> Vec<u8> {
    use hivepack::tar::{Header, Records, TYPE_DIR, TYPE_REG, Writer};
    use std::io::Write;
    let records = |pairs: &[(&str, &[u8])]| -> Records {
        pairs
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.to_vec()))
            .collect()
    };
    let mut tw = Writer::new(Vec::new());
    tw.write_header(&Header {
        typeflag: TYPE_DIR,
        name: b"d/".to_vec(),
        mode: 0o755,
        uid: i64::from(uid),
        gid: i64::from(gid),
        uname: user.as_bytes().to_vec(),
        gname: group.as_bytes().to_vec(),
        xattrs: records(&[("user.folder", b"kept")]),
        ..Header::default()
    })
    .unwrap();
    tw.write_header(&Header {
        typeflag: TYPE_REG,
        name: b"d/f".to_vec(),
        mode: 0o644,
        size: 5,
        uid: i64::from(uid),
        gid: i64::from(gid),
        uname: user.as_bytes().to_vec(),
        gname: group.as_bytes().to_vec(),
        xattrs: records(&[
            ("user.file", b"b\x00inary"),
            ("security.capability", b"\x01\x00\x00\x02"),
        ]),
        ..Header::default()
    })
    .unwrap();
    tw.write_all(b"hello").unwrap();
    tw.close().unwrap();
    tw.into_inner()
}

/// Owners and extended attributes are restored when asked, never
/// `security.capability`; otherwise what is extracted is the user's, bare. A
/// group the user is in is given; the owner, the user's own.
#[cfg(target_os = "linux")]
#[test]
fn owners_and_attributes_are_restored_when_asked() {
    use std::os::unix::fs::MetadataExt;
    let s = Scratch::new();
    let probe = s.path().join("probe");
    std::fs::write(&probe, "").unwrap();
    if rustix::fs::setxattr(&probe, "user.probe", b"x", rustix::fs::XattrFlags::empty()).is_err() {
        eprintln!("skipping: this file system takes no extended attributes");
        return;
    }
    let mine = std::fs::metadata(&probe).unwrap();
    // A group of the user's other than the one files get, if there is one.
    let other_gid = rustix::process::getgroups()
        .unwrap_or_default()
        .into_iter()
        .map(rustix::process::Gid::as_raw)
        .find(|&g| g != mine.gid())
        .unwrap_or(mine.gid());
    let archive = kept_for_a_backup(mine.uid(), other_gid);

    let bare = s.path().join("bare");
    extract(&archive, &bare, &options(|_| {})).unwrap();
    assert_eq!(xattr_of(&bare.join("d/f"), "user.file"), None);
    assert_eq!(xattr_of(&bare.join("d"), "user.folder"), None);
    assert_eq!(
        std::fs::metadata(bare.join("d/f")).unwrap().gid(),
        mine.gid()
    );

    let kept = s.path().join("kept");
    let restoring = options(|o| {
        o.owners = Owners::ByNumber;
        o.xattrs = true;
    });
    extract(&archive, &kept, &restoring).unwrap();
    let f = kept.join("d/f");
    assert_eq!(std::fs::read(&f).unwrap(), b"hello");
    assert_eq!(
        xattr_of(&f, "user.file").as_deref(),
        Some(&b"b\x00inary"[..])
    );
    assert_eq!(xattr_of(&f, "security.capability"), None);
    assert_eq!(
        xattr_of(&kept.join("d"), "user.folder").as_deref(),
        Some(&b"kept"[..])
    );
    let meta = std::fs::metadata(&f).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (mine.uid(), other_gid));
    assert_eq!(std::fs::metadata(kept.join("d")).unwrap().gid(), other_gid);
    // The time and permissions after them, as the archive has them.
    assert_eq!(meta.mode() & 0o777, 0o644);

    // The same with files written in threads.
    let threaded = s.path().join("threaded");
    let in_threads = options(|o| {
        o.owners = Owners::ByNumber;
        o.xattrs = true;
        o.threads = hivepack::Threads::of(4);
    });
    extract(&archive, &threaded, &in_threads).unwrap();
    let f = threaded.join("d/f");
    assert_eq!(
        xattr_of(&f, "user.file").as_deref(),
        Some(&b"b\x00inary"[..])
    );
    assert_eq!(std::fs::metadata(&f).unwrap().gid(), other_gid);

    // An owner the user may not give away is left as it is, and counted.
    let refused = s.path().join("refused");
    let summary = extract(
        &kept_for_a_backup(mine.uid() + 1, mine.gid()),
        &refused,
        &restoring,
    )
    .unwrap();
    if !rustix::process::geteuid().is_root() {
        assert_eq!(
            std::fs::metadata(refused.join("d/f")).unwrap().uid(),
            mine.uid()
        );
        assert_eq!(summary.owners_left, 2);
    }
}

/// The names of the user `uid` and the group `gid`, as the system looks them
/// up: none where it has no name for either, as in a container run under a
/// user it does not list (`cross`'s).
#[cfg(target_os = "linux")]
fn names_of(uid: u32, gid: u32) -> Option<(String, String)> {
    use nix::unistd::{Gid, Group, Uid, User};
    let user = User::from_uid(Uid::from_raw(uid)).ok()??.name;
    let group = Group::from_gid(Gid::from_raw(gid)).ok()??.name;
    Some((user, group))
}

/// By name, the system's user and group of those names, whatever numbers the
/// archive has; names it does not know, the archive's numbers. By number, the
/// names aside. An owner refused still gives its group, if it is the user's.
#[cfg(target_os = "linux")]
#[test]
fn owners_are_given_by_name_or_by_number() {
    use std::os::unix::fs::MetadataExt;
    let s = Scratch::new();
    let probe = s.path().join("probe");
    std::fs::write(&probe, "").unwrap();
    let mine = std::fs::metadata(&probe).unwrap();
    let root = rustix::process::geteuid().is_root();
    let other_gid = rustix::process::getgroups()
        .unwrap_or_default()
        .into_iter()
        .map(rustix::process::Gid::as_raw)
        .find(|&g| g != mine.gid())
        .unwrap_or(mine.gid());
    let owned = |dir: &Path| {
        let f = std::fs::metadata(dir.join("d/f")).unwrap();
        let d = std::fs::metadata(dir.join("d")).unwrap();
        assert_eq!((f.uid(), f.gid()), (d.uid(), d.gid()));
        (f.uid(), f.gid())
    };
    // Another's numbers, under the user's names: from another system.
    let names = names_of(mine.uid(), mine.gid());
    let (user, group) = names
        .as_ref()
        .map_or(("no-such-user-hp", "no-such-group-hp"), |(u, g)| {
            (u.as_str(), g.as_str())
        });
    let moved = kept_for_a_backup_named(mine.uid() + 1, other_gid, user, group);

    if names.is_some() {
        let by_name = s.path().join("by-name");
        let summary = extract(&moved, &by_name, &options(|o| o.owners = Owners::ByName)).unwrap();
        assert_eq!(owned(&by_name), (mine.uid(), mine.gid()));
        assert_eq!(summary.owners_left, 0);
    } else {
        eprintln!("skipping by name: the system has no name for the user or the group");
    }

    let by_number = s.path().join("by-number");
    let summary = extract(
        &moved,
        &by_number,
        &options(|o| o.owners = Owners::ByNumber),
    )
    .unwrap();
    if root {
        assert_eq!(owned(&by_number), (mine.uid() + 1, other_gid));
        assert_eq!(summary.owners_left, 0);
    } else {
        // The owner left, the group given.
        assert_eq!(owned(&by_number), (mine.uid(), other_gid));
        assert_eq!(summary.owners_left, 2);
    }

    // Names this system does not have: the numbers.
    let unknown = s.path().join("unknown");
    let summary = extract(
        &kept_for_a_backup_named(mine.uid(), other_gid, "no-such-user-hp", "no-such-group-hp"),
        &unknown,
        &options(|o| o.owners = Owners::ByName),
    )
    .unwrap();
    assert_eq!(owned(&unknown), (mine.uid(), other_gid));
    assert_eq!(summary.owners_left, 0);

    // Not asked: the user's.
    let bare = s.path().join("bare");
    let summary = extract(&moved, &bare, &options(|_| {})).unwrap();
    assert_eq!(owned(&bare), (mine.uid(), mine.gid()));
    assert_eq!(summary.owners_left, 0);
}

/// A sink that keeps the names of the files it is given, and writes nothing.
#[derive(Default)]
struct Names(Vec<String>);

impl Sink for Names {
    fn directory(&mut self, _: &Entry<'_>) -> std::io::Result<()> {
        Ok(())
    }

    fn start_file(&mut self, entry: &Entry<'_>) -> std::io::Result<()> {
        self.0.push(entry.path.join("/"));
        Ok(())
    }

    fn write(&mut self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    fn finish_file(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn discard_file(&mut self) {}

    fn symlink(&mut self, _: &Entry<'_>, _: &str) -> std::io::Result<()> {
        Ok(())
    }

    fn hard_link(&mut self, _: &Entry<'_>, _: &[String]) -> std::io::Result<()> {
        Ok(())
    }
}

/// Read once into a private folder, a tar archive refused at its last entry
/// leaves the destination as it was: what was there stays, nothing of the
/// archive appears, and no private folder is left.
#[test]
fn refused_at_its_end_the_destination_is_as_it_was() {
    let s = Scratch::new();
    std::fs::create_dir(s.out()).unwrap();
    std::fs::write(s.out().join("kept.txt"), "mine").unwrap();
    let data = tar(&[
        E::Dir(b"d/"),
        E::File(b"d/a.txt", b"one"),
        E::File(b"b.txt", b"two"),
        // The same path again, refused once the archive is read.
        E::File(b"B.TXT", b"three"),
    ]);
    let e = extract(&data, &s.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Duplicate { .. }), "{e}");
    assert_eq!(listing(&s.out()), ["kept.txt"]);
    assert_eq!(
        std::fs::read_to_string(s.out().join("kept.txt")).unwrap(),
        "mine"
    );
    // A destination made for it is gone too.
    let s = Scratch::new();
    extract(&data, &s.out(), &portable()).unwrap_err();
    assert!(!s.out().exists());
}

/// What is in the destination is found in the way before anything moves: a
/// file there stops the extraction, and nothing of the archive appears; with
/// `overwrite`, it is replaced, whole; a directory there is merged into.
#[test]
fn what_is_there_is_found_before_anything_moves() {
    let data = tar(&[
        E::Dir(b"d/"),
        E::File(b"d/new.txt", b"new"),
        E::File(b"a.txt", b"from the archive"),
    ]);
    let s = Scratch::new();
    std::fs::create_dir_all(s.out().join("d")).unwrap();
    std::fs::write(s.out().join("d/old.txt"), "old").unwrap();
    std::fs::write(s.out().join("a.txt"), "mine").unwrap();
    let e = extract(&data, &s.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Exists), "{e}");
    assert_eq!(listing(&s.out()), ["a.txt", "d/", "d/old.txt"]);
    assert_eq!(
        std::fs::read_to_string(s.out().join("a.txt")).unwrap(),
        "mine"
    );

    extract(&data, &s.out(), &options(|o| o.overwrite = true)).unwrap();
    assert_eq!(listing(&s.out()), ["a.txt", "d/", "d/new.txt", "d/old.txt"]);
    assert_eq!(
        std::fs::read_to_string(s.out().join("a.txt")).unwrap(),
        "from the archive"
    );
}

/// A private folder a process left, which no one holds, is removed by the next
/// extraction into the same place; one whose `owner` is held is not.
#[test]
fn a_private_folder_left_behind_is_removed_next_time() {
    let s = Scratch::new();
    let left = s.out().join(".hivepack-extracting-dead");
    std::fs::create_dir_all(left.join("data")).unwrap();
    std::fs::write(left.join("owner"), "").unwrap();
    std::fs::write(left.join("data/0"), "half a file").unwrap();
    let held = s.out().join(".hivepack-extracting-alive");
    std::fs::create_dir_all(&held).unwrap();
    let owner = std::fs::File::create(held.join("owner")).unwrap();
    owner.try_lock().unwrap();

    let data = tar(&[E::File(b"a.txt", b"one")]);
    extract(&data, &s.out(), &portable()).unwrap();
    assert!(!left.exists(), "left behind");
    assert!(held.exists(), "in use");
    drop(owner);
    extract(&tar(&[E::File(b"b.txt", b"two")]), &s.out(), &portable()).unwrap();
    assert_eq!(listing(&s.out()), ["a.txt", "b.txt"]);
}

/// `remove_stale` removes a private folder left behind without extracting:
/// what a program calls when it starts, for the places it extracted into.
#[test]
fn remove_stale_removes_what_no_one_holds() {
    let s = Scratch::new();
    std::fs::create_dir(s.out()).unwrap();
    let left = s.out().join(".hivepack-extracting-dead");
    std::fs::create_dir_all(left.join("data")).unwrap();
    std::fs::write(left.join("owner"), "").unwrap();
    let held = s.out().join(".hivepack-extracting-alive");
    std::fs::create_dir_all(&held).unwrap();
    let owner = std::fs::File::create(held.join("owner")).unwrap();
    owner.try_lock().unwrap();
    std::fs::write(s.out().join("mine.txt"), "mine").unwrap();
    remove_stale(&s.out()).unwrap();
    assert!(!left.exists());
    assert!(held.exists());
    assert!(s.out().join("mine.txt").exists());
    // Nothing there, nothing done.
    remove_stale(&s.path().join("not-there")).unwrap();
    assert!(!s.path().join("not-there").exists());
}
