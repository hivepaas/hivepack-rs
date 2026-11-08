//! Extracting tar and cpio archives with `Options::threads`: the archive read on
//! the caller's thread, its files written by others at once. What is written,
//! and the summary, are the same as with one thread; hard links wait for their
//! files, and damaged data, the limits, cancelling and the time limit stop it,
//! or are gone on from, as they do with one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::io::Cursor;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use hivepack::Threads;
use hivepack::extract::{
    Cancel, Error, ErrorKind, Links, OnDamaged, Options, Progress, Summary, extract_cpio,
    extract_tar, extract_tar_to,
};

/// The time the test entries have.
const MTIME: u64 = 1_600_000_000;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "hivepack-extract-tar-threads-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
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

/// What is under `dir`: each path, the length and a hash of what it holds or
/// leads to, its mode on Unix, whether it has the archive's time, and for a
/// file how many names it has.
fn contents(dir: &Path) -> Vec<String> {
    let archive_time = UNIX_EPOCH + Duration::from_secs(MTIME);
    listing(dir)
        .into_iter()
        .map(|path| {
            let at = dir.join(&path);
            let metadata = at.symlink_metadata().unwrap();
            let data = if metadata.is_symlink() {
                std::fs::read_link(&at)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
                    .into_bytes()
            } else if metadata.is_dir() {
                Vec::new()
            } else {
                std::fs::read(&at).unwrap()
            };
            #[cfg(unix)]
            let (mode, names) = {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let names = if metadata.is_file() {
                    metadata.nlink()
                } else {
                    0
                };
                (metadata.permissions().mode(), names)
            };
            #[cfg(not(unix))]
            let (mode, names) = (0, 0);
            // FNV-1a.
            let hash = data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
                (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
            });
            // A directory's time is set last, once nothing more is written in it.
            let dated = metadata.modified().unwrap() == archive_time;
            format!("{path} {} {hash:x} {mode:o} {dated} {names}", data.len())
        })
        .collect()
}

/// One thread, two, eight, and as many as the machine runs.
fn every_threads() -> [Threads; 4] {
    [
        Threads::One,
        Threads::Exactly(NonZeroU32::new(2).unwrap()),
        Threads::Exactly(NonZeroU32::new(8).unwrap()),
        Threads::Auto,
    ]
}

fn eight() -> Threads {
    Threads::Exactly(NonZeroU32::new(8).unwrap())
}

/// Text, different for each `seed`.
fn text(seed: usize, len: usize) -> Vec<u8> {
    let words = ["alpha ", "beta ", "gamma ", "delta ", "epsilon\n"];
    let mut out = Vec::with_capacity(len);
    let mut i = seed;
    while out.len() < len {
        out.extend_from_slice(words[i % words.len()].as_bytes());
        i = i.wrapping_mul(31).wrapping_add(7);
    }
    out.truncate(len);
    out
}

/// An entry of a test archive.
enum E {
    File(String, Vec<u8>, u32),
    Dir(String),
    Symlink(String, String),
    HardLink(String, String),
    /// A global PAX header, the archive's.
    Global,
}

/// A USTAR header block, its checksum written.
fn header(name: &str, typeflag: u8, size: u64, mode: u32, linkname: &str) -> Vec<u8> {
    let (name, linkname) = (name.as_bytes(), linkname.as_bytes());
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
fn tar(entries: &[E]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut add = |h: Vec<u8>, data: &[u8]| {
        out.extend(h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    };
    for entry in entries {
        match entry {
            E::File(name, data, mode) => {
                add(header(name, b'0', data.len() as u64, *mode, ""), data)
            }
            E::Dir(name) => add(header(name, b'5', 0, 0o755, ""), b""),
            E::Symlink(name, target) => add(header(name, b'2', 0, 0o777, target), b""),
            E::HardLink(name, target) => add(header(name, b'1', 0, 0o644, target), b""),
            E::Global => add(header("pax_global_header", b'g', 0, 0o644, ""), b""),
        }
    }
    out.extend([0u8; 1024]);
    out
}

/// The entries of an archive of many: directories with and without entries of
/// their own, one after its files, nested; empty files, small and larger ones,
/// one larger than what is handed to a thread; modes; hard links to files
/// written just before and long before; a symbolic link.
fn many() -> Vec<E> {
    let mut entries = vec![
        E::Global,
        E::File("late/first.txt".into(), text(9, 900), 0o644),
    ];
    for d in 0..4 {
        entries.push(E::Dir(format!("d{d}/")));
        for s in 0..3 {
            if s != 1 {
                entries.push(E::Dir(format!("d{d}/s{s}/")));
            }
            for f in 0..10 {
                let n = d * 100 + s * 20 + f;
                let (data, mode) = match f % 5 {
                    0 => (Vec::new(), 0o644),
                    1 => (text(n, 70_000 + n), 0o755),
                    2 => (text(n, 3 + n % 50), 0o4755),
                    _ => (text(n, 1000 + 37 * n), 0o600),
                };
                entries.push(E::File(format!("d{d}/s{s}/f{f}.txt"), data, mode));
            }
            entries.push(E::HardLink(
                format!("d{d}/s{s}/again"),
                format!("d{d}/s{s}/f9.txt"),
            ));
        }
    }
    entries.push(E::Dir("late/".into()));
    entries.push(E::File("big/one".into(), text(1, 5 << 20), 0o644));
    entries.push(E::HardLink("big/two".into(), "./d0/s0/f1.txt".into()));
    entries.push(E::Symlink("d0/link".into(), "s0/f1.txt".into()));
    entries
}

/// The names of the files, links and directories of [`many`], and the data of
/// each file.
fn files_of(entries: &[E]) -> Vec<(&str, &[u8])> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            E::File(name, data, _) => Some((name.as_str(), data.as_slice())),
            _ => None,
        })
        .collect()
}

/// What a summary says, to compare.
fn told(summary: &Summary) -> String {
    let damaged: Vec<_> = summary
        .damaged
        .iter()
        .map(|d| (d.error.index, format!("{:?}", d.error.kind), d.kept))
        .collect();
    let skipped: Vec<_> = summary.skipped.iter().map(|e| e.to_string()).collect();
    format!(
        "{} files, {} directories, {} links, {} bytes, skipped {skipped:?}, renamed {}, damaged {damaged:?}",
        summary.files,
        summary.directories,
        summary.links,
        summary.bytes,
        summary.renamed.len()
    )
}

fn with_threads(threads: Threads, change: impl FnOnce(&mut Options)) -> Options {
    let mut options = Options::default();
    options.name_rules = hivepack::extract::NameRules::Portable;
    options.threads = threads;
    options.links = Links::Inside;
    change(&mut options);
    options
}

fn extract(data: &[u8], out: &Path, options: &Options) -> Result<Summary, Error> {
    extract_tar(|| Ok(Cursor::new(data)), out, options)
}

/// What each thread was told, and by which thread.
type Told = Arc<Mutex<Vec<(Progress, std::thread::ThreadId)>>>;

fn recording(options: &mut Options) -> Told {
    let seen: Told = Arc::default();
    let record = Arc::clone(&seen);
    options.progress = Some(Arc::new(move |progress: &Progress| {
        record
            .lock()
            .unwrap()
            .push((*progress, std::thread::current().id()));
    }));
    seen
}

/// Told every piece and entry, never going back, up to the totals.
fn check_told(seen: &Told, summary: &Summary) -> usize {
    let seen = seen.lock().unwrap();
    for pair in seen.windows(2) {
        let (before, after) = (pair[0].0, pair[1].0);
        assert!(before.entries <= after.entries && before.bytes <= after.bytes);
    }
    let last = seen.last().unwrap().0;
    assert_eq!(
        (last.entries, last.bytes),
        (last.total_entries, last.total_bytes)
    );
    assert_eq!(last.bytes, summary.bytes);
    seen.iter().map(|(_, id)| *id).collect::<HashSet<_>>().len()
}

#[test]
fn what_is_written_is_the_same() {
    let entries = many();
    let data = tar(&entries);
    for links in [Links::Inside, Links::AsFile] {
        let mut first: Option<(String, Vec<String>)> = None;
        for threads in every_threads() {
            let scratch = Scratch::new();
            let mut options = with_threads(threads, |o| o.links = links);
            let seen = recording(&mut options);
            let summary = extract(&data, &scratch.out(), &options).unwrap();
            for (name, data) in files_of(&entries) {
                assert_eq!(
                    &std::fs::read(scratch.out().join(name)).unwrap(),
                    data,
                    "{name} with {threads:?}"
                );
            }
            let reporting = check_told(&seen, &summary);
            match threads {
                Threads::One => assert_eq!(reporting, 1),
                // Many files: the caller and others tell.
                Threads::Exactly(n) if n.get() == 8 => assert!(reporting > 1, "{threads:?}"),
                _ => {}
            }
            let found = (told(&summary), contents(&scratch.out()));
            match &first {
                None => first = Some(found),
                Some(first) => assert_eq!(first, &found, "{links:?} with {threads:?}"),
            }
        }
        let (summary, files) = first.unwrap();
        // 122 files, 13 hard links, 13 directories (`late/` among them), a link,
        // which is a file with `Links::AsFile`.
        let expected = match links {
            Links::AsFile => "136 files, 13 directories, 0 links",
            _ => "135 files, 13 directories, 1 links",
        };
        assert!(summary.starts_with(expected), "{summary}");
        assert!(files.len() > 140, "{}", files.len());
    }
}

/// A newc cpio archive (`070701`) of `entries`: name, mode, data, inode and
/// number of names, then `TRAILER!!!`.
fn newc(entries: &[(&str, u32, &[u8], u32, u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut put = |name: &[u8], mode: u32, data: &[u8], ino: u32, nlink: u32| {
        let fields = [
            ino,
            mode,
            0,
            0,
            nlink,
            MTIME as u32,
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
    for &(name, mode, data, ino, nlink) in entries {
        put(name.as_bytes(), mode, data, ino, nlink);
    }
    put(b"TRAILER!!!", 0, b"", 0, 1);
    out
}

#[test]
fn cpio_is_written_the_same() {
    let bodies: Vec<Vec<u8>> = (0..60).map(|i| text(i, 100 + 997 * i)).collect();
    let names: Vec<String> = (0..60).map(|i| format!("usr/lib/f{i:02}")).collect();
    let links: Vec<String> = (0..3).map(|i| format!("usr/bin/l{i}")).collect();
    let mut entries: Vec<(&str, u32, &[u8], u32, u32)> = vec![
        (".", 0o040755, b"", 1, 2),
        ("usr", 0o040755, b"", 2, 2),
        ("usr/lib", 0o040755, b"", 3, 2),
    ];
    for (i, (name, body)) in names.iter().zip(&bodies).enumerate() {
        entries.push((name, 0o100644, body, 100 + i as u32, 1));
        if i == 30 {
            // A file of three names, its data with the last, as GNU cpio and
            // RPM write it: the first two wait for it.
            entries.push((&links[0], 0o100755, b"", 9, 3));
            entries.push((&links[1], 0o100755, b"", 9, 3));
            entries.push((&links[2], 0o100755, &bodies[3], 9, 3));
        }
    }
    entries.push(("usr/bin", 0o040755, b"", 4, 2));
    entries.push(("usr/bin/sh", 0o120777, b"l0", 5, 1));
    let data = newc(&entries);
    let mut first: Option<(String, Vec<String>)> = None;
    for threads in every_threads() {
        let scratch = Scratch::new();
        let mut options = with_threads(threads, |_| {});
        let seen = recording(&mut options);
        let summary = extract_cpio(|| Ok(Cursor::new(&data)), &scratch.out(), &options).unwrap();
        check_told(&seen, &summary);
        let found = (told(&summary), contents(&scratch.out()));
        match &first {
            None => first = Some(found),
            Some(first) => assert_eq!(first, &found, "{threads:?}"),
        }
    }
    let (summary, files) = first.unwrap();
    assert!(
        summary.starts_with("63 files, 3 directories, 1 links"),
        "{summary}"
    );
    #[cfg(unix)]
    assert!(
        files
            .iter()
            .any(|f| f.starts_with("usr/bin/l0 ") && f.ends_with(" 3"))
    );
    assert!(files.len() > 60);
}

/// [`many`] cut short in the data of a file of 70 kB, after `d2/s0/`: the
/// first reading stops there unless told to go on.
fn cut_short() -> (Vec<u8>, usize) {
    let entries = many();
    let data = tar(&entries);
    let body = files_of(&entries)
        .into_iter()
        .find(|(name, _)| *name == "d2/s0/f6.txt")
        .unwrap()
        .1;
    let at = data.windows(body.len()).position(|w| w == body).unwrap();
    let index = entries
        .iter()
        .position(|e| matches!(e, E::File(name, ..) if name == "d2/s0/f6.txt"))
        .unwrap();
    (data[..at + 30_000].to_vec(), index)
}

#[test]
fn damaged_data_is_the_same() {
    let (data, index) = cut_short();
    for threads in every_threads() {
        // Stopping, the default: before anything is written.
        let scratch = Scratch::new();
        let error = extract(&data, &scratch.out(), &with_threads(threads, |_| {})).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Tar(_)), "{error}");
        assert!(!scratch.out().exists());
    }

    // Asked about once, and gone on from: the same summary and files.
    for how in [OnDamaged::Skip, OnDamaged::Keep] {
        let mut first = None;
        for threads in every_threads() {
            let scratch = Scratch::new();
            let asked = Arc::new(Mutex::new(Vec::new()));
            let record = Arc::clone(&asked);
            let options = with_threads(threads, |o| {
                o.on_damaged = Some(Arc::new(move |error: &Error| {
                    record.lock().unwrap().push(error.index);
                    how
                }));
            });
            let summary = extract(&data, &scratch.out(), &options).unwrap();
            assert_eq!(*asked.lock().unwrap(), [Some(index as u64)]);
            let damaged: Vec<_> = summary.damaged.iter().map(|d| d.error.index).collect();
            assert_eq!(damaged, [Some(index as u64)]);
            let found = (told(&summary), contents(&scratch.out()));
            match &first {
                None => first = Some(found),
                Some(first) => assert_eq!(first, &found, "{how:?} with {threads:?}"),
            }
        }
    }
}

#[test]
fn an_archive_that_changes_stops() {
    let entries = many();
    let data = tar(&entries);
    // The second reading finds a file of another size.
    let mut changed = data.clone();
    let at = changed
        .windows(16)
        .position(|w| w.starts_with(b"d3/s2/f4.txt\0"))
        .unwrap();
    let size = changed[at + 124..at + 136].to_vec();
    let mut other = header("d3/s2/f4.txt", b'0', 1, 0o600, "");
    other[124..136].copy_from_slice(&size);
    other[124 + 10] ^= 1;
    changed[at..at + 512].copy_from_slice(&header_with_sum(other));
    for threads in every_threads() {
        // Into a folder it is read once: what the one reading reads is written.
        let scratch = Scratch::new();
        let mut reads = 0;
        extract_tar(
            || {
                reads += 1;
                Ok(Cursor::new(if reads == 1 { &data } else { &changed }))
            },
            &scratch.out(),
            &with_threads(threads, |_| {}),
        )
        .unwrap();
        assert_eq!(reads, 1, "{threads:?}");
        for (name, body) in files_of(&entries) {
            assert_eq!(
                &std::fs::read(scratch.out().join(name)).unwrap(),
                body,
                "{name}"
            );
        }
        // Into a sink it is read twice, and the change stops it.
        let mut reads = 0;
        let mut sink = Nothing;
        let error = extract_tar_to(
            || {
                reads += 1;
                Ok(Cursor::new(if reads == 1 { &data } else { &changed }))
            },
            &mut sink,
            &with_threads(threads, |_| {}),
        )
        .unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Changed), "{error}");
    }
}

/// `b` with its checksum written again.
fn header_with_sum(mut b: Vec<u8>) -> Vec<u8> {
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&c| u32::from(c)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    b
}

#[test]
fn a_file_that_cannot_be_written_stops_every_thread() {
    let entries = many();
    let data = tar(&entries);
    let index = entries
        .iter()
        .position(|e| matches!(e, E::File(name, ..) if name == "d1/s2/f3.txt"))
        .unwrap();
    for threads in every_threads() {
        // A directory where the file is to be: nothing is written over it.
        let scratch = Scratch::new();
        std::fs::create_dir_all(scratch.out().join("d1/s2/f3.txt")).unwrap();
        let error = extract(&data, &scratch.out(), &with_threads(threads, |_| {})).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Exists), "{error}");
        assert_eq!(error.index, Some(index as u64));
        assert!(scratch.out().join("d1/s2/f3.txt").is_dir());
        // No link is created after an error.
        assert!(!scratch.out().join("d0/link").exists());
        for (name, body) in files_of(&entries) {
            let at = scratch.out().join(name);
            if at.is_file() {
                assert_eq!(&std::fs::read(&at).unwrap(), body, "{name}");
            }
        }
    }
}

#[test]
fn the_limits_stop_it() {
    let data = tar(&many());
    for threads in every_threads() {
        // The archive says too much: nothing is written.
        let scratch = Scratch::new();
        let options = with_threads(threads, |o| o.limits.max_total_size = 1_000_000);
        let error = extract(&data, &scratch.out(), &options).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::TotalTooLarge), "{error}");
        assert!(!scratch.out().exists());
    }
}

#[test]
fn a_memory_limit_writes_the_same() {
    let entries = many();
    let data = tar(&entries);
    let one = Scratch::new();
    let summary = extract(&data, &one.out(), &with_threads(Threads::One, |_| {})).unwrap();
    // Files of more than 8 kB written on the caller's thread, the others by
    // the threads, 64 kB at most held.
    for limit in [0, 64 << 10] {
        let scratch = Scratch::new();
        let options = with_threads(eight(), |o| o.memory_limit = Some(limit));
        let limited = extract(&data, &scratch.out(), &options).unwrap();
        assert_eq!(told(&summary), told(&limited));
        assert_eq!(contents(&one.out()), contents(&scratch.out()));
    }
}

#[test]
fn cancelling_stops_it() {
    let entries = many();
    let data = tar(&entries);
    for threads in every_threads() {
        // Before anything is written.
        let scratch = Scratch::new();
        let cancel = Cancel::new();
        cancel.cancel();
        let options = with_threads(threads, |o| o.cancel = Some(cancel));
        let error = extract(&data, &scratch.out(), &options).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Cancelled), "{error}");
        assert!(!scratch.out().exists());

        let scratch = Scratch::new();
        let options = with_threads(threads, |o| o.time_limit = Some(Duration::ZERO));
        let error = extract(&data, &scratch.out(), &options).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::TimeLimit), "{error}");
        assert!(!scratch.out().exists());

        // Once a megabyte is written: every thread stops, and what was cut
        // off is removed.
        let scratch = Scratch::new();
        let cancel = Cancel::new();
        let token = cancel.clone();
        let options = with_threads(threads, |o| {
            o.cancel = Some(cancel);
            o.progress = Some(Arc::new(move |progress: &Progress| {
                if progress.bytes > 1 << 20 {
                    token.cancel();
                }
            }));
        });
        let error = extract(&data, &scratch.out(), &options).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Cancelled), "{error}");
        let mut written = 0;
        for (name, body) in files_of(&entries) {
            let at = scratch.out().join(name);
            if at.is_file() {
                assert_eq!(
                    &std::fs::read(&at).unwrap(),
                    body,
                    "{name} with {threads:?}"
                );
                written += 1;
            }
        }
        assert!(written < 100, "{written} with {threads:?}");
        assert!(!scratch.out().join("big/one").exists());
    }
}

/// A sink is given the entries in order, on the caller's thread, whatever the
/// threads.
#[test]
fn a_sink_is_given_the_same() {
    #[derive(Default)]
    struct Names(Vec<String>, HashSet<std::thread::ThreadId>);
    impl Names {
        fn note(&mut self, what: String) {
            self.0.push(what);
            self.1.insert(std::thread::current().id());
        }
    }
    impl hivepack::extract::Sink for Names {
        fn directory(&mut self, entry: &hivepack::extract::Entry<'_>) -> std::io::Result<()> {
            self.note(entry.path.join("/"));
            Ok(())
        }
        fn start_file(&mut self, entry: &hivepack::extract::Entry<'_>) -> std::io::Result<()> {
            self.note(entry.path.join("/"));
            Ok(())
        }
        fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
            self.note(data.len().to_string());
            Ok(())
        }
        fn finish_file(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        fn discard_file(&mut self) {}
        fn symlink(
            &mut self,
            entry: &hivepack::extract::Entry<'_>,
            target: &str,
        ) -> std::io::Result<()> {
            self.note(format!("{} -> {target}", entry.path.join("/")));
            Ok(())
        }
        fn hard_link(
            &mut self,
            entry: &hivepack::extract::Entry<'_>,
            target: &[String],
        ) -> std::io::Result<()> {
            self.note(format!("{} = {}", entry.path.join("/"), target.join("/")));
            Ok(())
        }
    }
    let data = tar(&many());
    let open = || Ok(Cursor::new(&data));
    let mut one = Names::default();
    extract_tar_to(open, &mut one, &with_threads(Threads::One, |_| {})).unwrap();
    let mut eight_threads = Names::default();
    extract_tar_to(open, &mut eight_threads, &with_threads(eight(), |_| {})).unwrap();
    assert_eq!(one.0, eight_threads.0);
    assert_eq!(eight_threads.1.len(), 1);
}

/// A sink that writes nothing.
struct Nothing;

impl hivepack::extract::Sink for Nothing {
    fn directory(&mut self, _: &hivepack::extract::Entry<'_>) -> std::io::Result<()> {
        Ok(())
    }
    fn start_file(&mut self, _: &hivepack::extract::Entry<'_>) -> std::io::Result<()> {
        Ok(())
    }
    fn write(&mut self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn finish_file(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn discard_file(&mut self) {}
    fn symlink(&mut self, _: &hivepack::extract::Entry<'_>, _: &str) -> std::io::Result<()> {
        Ok(())
    }
    fn hard_link(&mut self, _: &hivepack::extract::Entry<'_>, _: &[String]) -> std::io::Result<()> {
        Ok(())
    }
}
