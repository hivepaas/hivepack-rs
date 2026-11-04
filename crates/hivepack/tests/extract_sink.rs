//! Extracting into a `Sink` in place of a folder: for each format, what a sink is
//! given is what the same extraction writes to disk, in the order a folder's
//! extraction writes it; the checks, the limits, a file whose data fails, and a
//! sink that fails stop it as they stop one to disk.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::io::{self, Cursor};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hivepack::extract::{
    Entry, ErrorKind, Links, NameError, OnRefused, Options, Permissions, Sink, Summary, extract_7z,
    extract_7z_to, extract_cpio, extract_cpio_to, extract_tar, extract_tar_to, extract_udf,
    extract_udf_to, extract_xar, extract_xar_to, extract_zip, extract_zip_to,
};
use hivepack::zip::{Archive, OpenFlags};

use support::{Entry as Z, Scratch};

/// What a sink was given.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Given {
    Dir(String),
    File(String, Vec<u8>),
    Symlink(String, String),
    HardLink(String, String),
}

/// A sink that keeps what it is given, and checks it is given it in turn.
#[derive(Default)]
struct Recorder {
    given: Vec<Given>,
    /// The file being given: its path, the size it said, and its data so far.
    file: Option<(String, Option<u64>, Vec<u8>)>,
    times: BTreeMap<String, SystemTime>,
    modes: BTreeMap<String, u32>,
    discarded: Vec<String>,
    /// Fails the write that would take a file past this many bytes.
    fail_after: Option<usize>,
}

fn joined(path: &[String]) -> String {
    assert!(!path.is_empty());
    path.join("/")
}

impl Recorder {
    fn note(&mut self, entry: &Entry<'_>) -> String {
        assert!(self.file.is_none(), "{:?} while a file is open", entry.path);
        let path = joined(entry.path);
        if let Some(mtime) = entry.mtime {
            self.times.insert(path.clone(), mtime);
        }
        if let Some(mode) = entry.mode {
            self.modes.insert(path.clone(), mode);
        }
        path
    }
}

impl Sink for Recorder {
    fn directory(&mut self, entry: &Entry<'_>) -> io::Result<()> {
        let path = self.note(entry);
        self.given.push(Given::Dir(path));
        Ok(())
    }

    fn start_file(&mut self, entry: &Entry<'_>) -> io::Result<()> {
        let path = self.note(entry);
        self.file = Some((path, entry.size, Vec::new()));
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let fail_after = self.fail_after;
        let (_, _, so_far) = self.file.as_mut().expect("data with no file open");
        if fail_after.is_some_and(|most| so_far.len() + data.len() > most) {
            return Err(io::Error::other("the sink is full"));
        }
        so_far.extend_from_slice(data);
        Ok(())
    }

    fn finish_file(&mut self) -> io::Result<()> {
        let (path, size, data) = self.file.take().expect("a file ended that did not start");
        if let Some(size) = size {
            assert_eq!(size, data.len() as u64, "{path}");
        }
        self.given.push(Given::File(path, data));
        Ok(())
    }

    fn discard_file(&mut self) {
        let (path, _, _) = self
            .file
            .take()
            .expect("a file discarded that did not start");
        self.discarded.push(path);
    }

    fn symlink(&mut self, entry: &Entry<'_>, target: &str) -> io::Result<()> {
        let path = self.note(entry);
        self.given.push(Given::Symlink(path, target.to_string()));
        Ok(())
    }

    fn hard_link(&mut self, entry: &Entry<'_>, target: &[String]) -> io::Result<()> {
        let path = self.note(entry);
        self.given.push(Given::HardLink(path, joined(target)));
        Ok(())
    }
}

/// What is under `dir`: each directory, file with its data, and symbolic link
/// with its target, by path with `/`.
fn tree(dir: &Path) -> BTreeMap<String, Given> {
    let mut found = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            let relative = path
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let metadata = path.symlink_metadata().unwrap();
            let given = if metadata.is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                Given::Symlink(
                    relative.clone(),
                    target.to_string_lossy().replace('\\', "/"),
                )
            } else if metadata.is_dir() {
                stack.push(path);
                Given::Dir(relative.clone())
            } else {
                Given::File(relative.clone(), std::fs::read(&path).unwrap())
            };
            found.insert(relative, given);
        }
    }
    found
}

/// What `given` makes on disk: hard links as files with their target's data, and
/// the directories on the way to each entry.
fn as_tree(given: &[Given]) -> BTreeMap<String, Given> {
    let mut found = BTreeMap::new();
    let mut data = BTreeMap::new();
    let mut given_paths = std::collections::BTreeSet::new();
    for g in given {
        let path = match g {
            Given::Dir(path) | Given::Symlink(path, _) => path,
            Given::File(path, bytes) => {
                data.insert(path.clone(), bytes.clone());
                path
            }
            Given::HardLink(path, target) => {
                let bytes = data.get(target).cloned().expect("a link before its file");
                data.insert(path.clone(), bytes.clone());
                found.insert(path.clone(), Given::File(path.clone(), bytes));
                path
            }
        };
        assert!(given_paths.insert(path.clone()), "{path} twice");
        if !matches!(g, Given::HardLink(..)) {
            found.insert(path.clone(), g.clone());
        }
        let mut parent = path.as_str();
        while let Some((up, _)) = parent.rsplit_once('/') {
            found
                .entry(up.to_string())
                .or_insert_with(|| Given::Dir(up.to_string()));
            parent = up;
        }
    }
    found
}

/// Checks that what `recorder` was given is what is under `out`, the times and
/// permission bits among it, and that the summaries agree.
fn same(out: &Path, disk: &Summary, recorder: &Recorder, sink: &Summary) {
    assert_eq!(as_tree(&recorder.given), tree(out));
    assert_eq!(
        (
            disk.files,
            disk.directories,
            disk.links,
            disk.bytes,
            disk.skipped.len()
        ),
        (
            sink.files,
            sink.directories,
            sink.links,
            sink.bytes,
            sink.skipped.len()
        ),
    );
    assert!(recorder.file.is_none() && recorder.discarded.is_empty());
    for g in &recorder.given {
        let (Given::File(path, _) | Given::Dir(path)) = g else {
            continue;
        };
        let metadata = std::fs::metadata(out.join(path)).unwrap();
        // A 32-bit system's `time_t` ends in January 2038: a file dated after
        // keeps the time it was written at on disk, and the sink is given its
        // own.
        let ends = UNIX_EPOCH + Duration::from_secs(i32::MAX as u64);
        let held = |t: &&SystemTime| !cfg!(target_pointer_width = "32") || **t <= ends;
        if let Some(&mtime) = recorder.times.get(path).filter(held) {
            let on_disk = metadata.modified().unwrap();
            let apart = on_disk
                .duration_since(mtime)
                .or_else(|_| mtime.duration_since(on_disk))
                .unwrap();
            assert!(apart < Duration::from_secs(1), "{path}: {apart:?}");
        }
        #[cfg(unix)]
        if let (Some(&mode), Given::File(..)) = (recorder.modes.get(path), g) {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o7777, mode, "{path}");
        }
    }
}

/// The options both extractions take: links kept, inside, and what is refused
/// left out, as the test archives of some formats have names refused.
fn options() -> Options {
    support::options(|o| {
        o.links = Links::Inside;
        o.on_refused = OnRefused::Skip;
    })
}

fn zip_archive() -> Vec<u8> {
    support::zip(&[
        Z::DirAt(b"docs/"),
        Z::File(b"docs/notes.txt", b"notes"),
        Z::Mode(b"run.sh", b"#!/bin/sh\n", 0o100_755),
        Z::Stored(b"docs/deep/stored.bin", &[7; 3000]),
        Z::Mode(b"docs/link", b"notes.txt", 0o120_777),
        Z::File(b"empty", b""),
    ])
}

#[test]
fn zip_gives_what_it_writes() {
    let data = zip_archive();
    let archive = Archive::open(&data[..], OpenFlags::CHECKCONS).unwrap();
    let scratch = Scratch::new();
    let disk = extract_zip(&archive, &scratch.out(), &options()).unwrap();
    let mut recorder = Recorder::default();
    let sink = extract_zip_to(&archive, &mut recorder, &options()).unwrap();
    same(&scratch.out(), &disk, &recorder, &sink);
    // In the archive's order, the link last.
    assert_eq!(recorder.given[0], Given::Dir("docs".into()));
    assert_eq!(
        recorder.given.last(),
        Some(&Given::Symlink("docs/link".into(), "notes.txt".into()))
    );
    assert_eq!(recorder.modes.get("run.sh"), Some(&0o755));
}

#[test]
fn permissions_are_given_as_the_options_say() {
    let data = support::zip(&[Z::Mode(b"set", b"x", 0o104_777)]);
    let archive = Archive::open(&data[..], OpenFlags::CHECKCONS).unwrap();
    for (permissions, mode) in [
        (Permissions::Masked, Some(0o755)),
        (Permissions::Preserve, Some(0o777)),
        (Permissions::Ignore, None),
    ] {
        let mut recorder = Recorder::default();
        let options = support::options(|o| o.permissions = permissions);
        extract_zip_to(&archive, &mut recorder, &options).unwrap();
        assert_eq!(recorder.modes.get("set").copied(), mode, "{permissions:?}");
    }
}

#[test]
fn a_refused_name_gives_nothing() {
    let data = support::zip(&[Z::File(b"fine", b"x"), Z::File(b"../up", b"y")]);
    let archive = Archive::open(&data[..], OpenFlags::CHECKCONS).unwrap();
    let mut recorder = Recorder::default();
    let e = extract_zip_to(&archive, &mut recorder, &Options::default()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Name(NameError::Dot)), "{e}");
    assert!(recorder.given.is_empty());
}

#[test]
fn data_that_fails_is_discarded() {
    let mut data = support::zip(&[
        Z::Stored(b"good", b"good data"),
        Z::Stored(b"bad", b"bad data"),
    ]);
    // The last byte of the second file's data, which its CRC-32 no longer takes.
    let at = data.windows(8).rposition(|w| w == b"bad data").unwrap() + 7;
    data[at] ^= 1;
    let archive = Archive::open(&data[..], OpenFlags::CHECKCONS).unwrap();
    let mut recorder = Recorder::default();
    let e = extract_zip_to(&archive, &mut recorder, &Options::default()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Archive(_)), "{e}");
    assert_eq!(
        recorder.given,
        [Given::File("good".into(), b"good data".to_vec())]
    );
    assert_eq!(recorder.discarded, ["bad"]);
}

#[test]
fn the_limits_count_what_is_given() {
    let data = zip_archive();
    let archive = Archive::open(&data[..], OpenFlags::CHECKCONS).unwrap();
    let mut recorder = Recorder::default();
    let options = support::limits(|l| l.max_entry_size = 1000);
    let e = extract_zip_to(&archive, &mut recorder, &options).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::EntryTooLarge), "{e}");
    assert!(recorder.given.is_empty());
}

#[test]
fn a_sink_that_fails_stops_it() {
    let data = zip_archive();
    let archive = Archive::open(&data[..], OpenFlags::CHECKCONS).unwrap();
    let mut recorder = Recorder {
        fail_after: Some(100),
        ..Recorder::default()
    };
    let e = extract_zip_to(&archive, &mut recorder, &options()).unwrap_err();
    assert!(
        matches!(&e.kind, ErrorKind::Io(io) if io.to_string() == "the sink is full"),
        "{e}"
    );
    assert_eq!(recorder.discarded, ["docs/deep/stored.bin"]);
}

/// A USTAR header block, its checksum written.
fn tar_header(name: &[u8], typeflag: u8, size: u64, mode: u32, linkname: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[..name.len()].copy_from_slice(name);
    b[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
    b[108..116].copy_from_slice(b"0001750\0");
    b[116..124].copy_from_slice(b"0001750\0");
    b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    b[136..148].copy_from_slice(format!("{:011o}\0", support::MTIME).as_bytes());
    b[156] = typeflag;
    b[157..157 + linkname.len()].copy_from_slice(linkname);
    b[257..265].copy_from_slice(b"ustar\x0000");
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&c| u32::from(c)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    b
}

/// A tar archive with a directory, files, a symbolic and a hard link.
fn tar_archive() -> Vec<u8> {
    let mut out = Vec::new();
    let mut add = |h: Vec<u8>, data: &[u8]| {
        out.extend(h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    };
    add(tar_header(b"dir/", b'5', 0, 0o755, b""), b"");
    add(tar_header(b"dir/a.txt", b'0', 5, 0o644, b""), b"hello");
    add(tar_header(b"zeros", b'0', 70_000, 0o600, b""), &[0; 70_000]);
    add(tar_header(b"dir/again", b'1', 0, 0o644, b"dir/a.txt"), b"");
    add(tar_header(b"to-a", b'2', 0, 0o777, b"dir/a.txt"), b"");
    out.extend([0u8; 1024]);
    out
}

#[test]
fn tar_gives_what_it_writes() {
    let data = tar_archive();
    let open = || Ok(Cursor::new(data.clone()));
    let scratch = Scratch::new();
    let disk = extract_tar(open, &scratch.out(), &options()).unwrap();
    let mut recorder = Recorder::default();
    let sink = extract_tar_to(open, &mut recorder, &options()).unwrap();
    same(&scratch.out(), &disk, &recorder, &sink);
    assert!(
        recorder
            .given
            .contains(&Given::HardLink("dir/again".into(), "dir/a.txt".into()))
    );
}

#[test]
fn a_hard_link_is_given_as_one_whatever_the_options() {
    let data = tar_archive();
    let mut recorder = Recorder::default();
    let options = support::options(|o| o.links = Links::AsFile);
    extract_tar_to(|| Ok(Cursor::new(data.clone())), &mut recorder, &options).unwrap();
    assert!(
        recorder
            .given
            .contains(&Given::HardLink("dir/again".into(), "dir/a.txt".into()))
    );
    // A symbolic link, with AsFile, is a file of its target.
    assert!(
        recorder
            .given
            .contains(&Given::File("to-a".into(), b"dir/a.txt".to_vec()))
    );
}

/// A newc cpio archive of a directory, a file and a symbolic link.
fn cpio_archive() -> Vec<u8> {
    let mut out = Vec::new();
    let mut put = |name: &[u8], mode: u32, data: &[u8], ino: u32| {
        let fields = [
            ino,
            mode,
            0,
            0,
            1,
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
    put(b"dir", 0o040_755, b"", 1);
    put(b"dir/file", 0o100_640, b"cpio data", 2);
    put(b"link", 0o120_777, b"dir/file", 3);
    put(b"TRAILER!!!", 0, b"", 0);
    out
}

#[test]
fn cpio_gives_what_it_writes() {
    let data = cpio_archive();
    let open = || Ok(Cursor::new(data.clone()));
    let scratch = Scratch::new();
    let disk = extract_cpio(open, &scratch.out(), &options()).unwrap();
    let mut recorder = Recorder::default();
    let sink = extract_cpio_to(open, &mut recorder, &options()).unwrap();
    same(&scratch.out(), &disk, &recorder, &sink);
    assert_eq!(recorder.given.len(), 3);
}

#[test]
fn seven_zip_gives_what_it_writes() {
    for name in [
        "plain.7z",
        "cases.7z",
        "links.7z",
        "modes.7z",
        "deflate.7z",
        "bcj2.7z",
    ] {
        let data = std::fs::read(support::repository().join("testdata/7z").join(name)).unwrap();
        let open = || hivepack::sevenz::Archive::open(Cursor::new(data.clone())).unwrap();
        let scratch = Scratch::new();
        let disk = extract_7z(&mut open(), &scratch.out(), &options());
        let mut recorder = Recorder::default();
        let sink = extract_7z_to(&mut open(), &mut recorder, &options());
        match (disk, sink) {
            (Ok(disk), Ok(sink)) => same(&scratch.out(), &disk, &recorder, &sink),
            (Err(disk), Err(sink)) => assert_eq!(disk.to_string(), sink.to_string(), "{name}"),
            (disk, sink) => panic!("{name}: {disk:?} and {sink:?}"),
        }
    }
}

#[test]
fn udf_gives_what_it_writes() {
    let dir = support::repository().join("testdata/udf");
    for name in ["mkudffs-hd-0102", "mkudffs-dvdr-0250", "genisoimage"] {
        let image = support::xz_decode(&std::fs::read(dir.join(format!("{name}.udf.xz"))).unwrap());
        let open = || hivepack::udf::Udf::open(Cursor::new(image.clone())).unwrap();
        let scratch = Scratch::new();
        let disk = extract_udf(&mut open(), &scratch.out(), &options()).unwrap();
        let mut recorder = Recorder::default();
        let sink = extract_udf_to(&mut open(), &mut recorder, &options()).unwrap();
        same(&scratch.out(), &disk, &recorder, &sink);
    }
}

#[test]
fn xar_gives_what_it_writes_and_payloads_under_their_package() {
    for name in ["default.xar", "none-sha256.xar", "tiny.pkg", "product.pkg"] {
        let data = std::fs::read(support::repository().join("testdata/xar").join(name)).unwrap();
        let open = || Ok(Cursor::new(data.clone()));
        let scratch = Scratch::new();
        let disk = extract_xar(open, &scratch.out(), &options()).unwrap();
        let mut recorder = Recorder::default();
        let sink = extract_xar_to(open, &mut recorder, &options()).unwrap();
        same(&scratch.out(), &disk, &recorder, &sink);
        if name == "tiny.pkg" {
            assert!(
                recorder
                    .given
                    .iter()
                    .any(|g| matches!(g, Given::File(path, _) if path.starts_with("Payload/"))),
                "{:?}",
                recorder.given
            );
        }
    }
}

#[cfg(feature = "rar")]
#[test]
fn rar_gives_what_it_writes() {
    use hivepack::extract::{extract_rar, extract_rar_to};
    for name in [
        "rar4-m3.rar",
        "rar4-m5-solid.rar",
        "rar5-m3.rar",
        "rar5-m3-solid.rar",
    ] {
        let data = std::fs::read(support::repository().join("testdata/rar").join(name)).unwrap();
        let open =
            |password: &str| hivepack::rar::Archive::open_with_password(&data[..], false, password);
        let scratch = Scratch::new();
        let disk = extract_rar(open, &scratch.out(), &options()).unwrap();
        let mut recorder = Recorder::default();
        let sink = extract_rar_to(open, &mut recorder, &options()).unwrap();
        same(&scratch.out(), &disk, &recorder, &sink);
    }
}

#[test]
fn times_are_given() {
    let data = zip_archive();
    let archive = Archive::open(&data[..], OpenFlags::CHECKCONS).unwrap();
    let mut recorder = Recorder::default();
    extract_zip_to(&archive, &mut recorder, &options()).unwrap();
    let at = UNIX_EPOCH + Duration::from_secs(support::MTIME as u64);
    assert_eq!(recorder.times.get("docs/notes.txt"), Some(&at));
    assert_eq!(recorder.times.get("docs"), Some(&at));
}
