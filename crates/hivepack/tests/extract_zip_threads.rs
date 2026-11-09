//! Extracting a ZIP archive with `Options::threads`: files written several at
//! once, each in a thread of its own. What is written, and the summary, are the
//! same as with one thread; damaged data, the limits, cancelling and the time
//! limit stop it, or are gone on from, as they do with one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "threads_support/mod.rs"]
mod threads_support;

#[path = "extract_support/mod.rs"]
mod support;

use std::collections::HashSet;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use hivepack::Threads;
use hivepack::extract::{
    Cancel, Error, ErrorKind, Links, OnDamaged, Options, Progress, Summary, extract_zip_to,
};
use hivepack::zip::{Archive, OpenFlags};
use support::{Entry, MTIME, Scratch, extract, listing, options, zip};

/// One thread, two, eight, and as many as the machine runs.
fn every_threads() -> Vec<Threads> {
    threads_support::chosen([
        Threads::One,
        Threads::Exactly(NonZeroU32::new(2).unwrap()),
        Threads::Exactly(NonZeroU32::new(8).unwrap()),
        Threads::Auto,
    ])
}

/// Text that deflates, different for each `seed`.
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

/// The names and data of an archive of many entries: directories with and
/// without entries of their own, nested, empty files, stored and deflated ones,
/// and files with modes; a link, on Unix.
fn many() -> Vec<(String, Vec<u8>, u32)> {
    let mut entries = Vec::new();
    for d in 0..6 {
        entries.push((format!("d{d}/"), Vec::new(), 0));
        for s in 0..3 {
            if s != 1 {
                entries.push((format!("d{d}/s{s}/"), Vec::new(), 0));
            }
            for f in 0..12 {
                let n = d * 100 + s * 20 + f;
                let (data, mode) = match f % 6 {
                    0 => (Vec::new(), 0),
                    1 => (text(n, 70_000 + n), 0o100_755),
                    2 => (text(n, 3 + n % 50), 0o100_644),
                    _ => (text(n, 1000 + 37 * n), 0),
                };
                entries.push((format!("d{d}/s{s}/f{f}.txt"), data, mode));
            }
        }
    }
    entries.push(("top/deep/er/still/file".into(), text(1, 200_000), 0));
    if cfg!(unix) {
        entries.push(("d0/link".into(), b"s0/f1.txt".to_vec(), 0o120_777));
    }
    entries
}

fn many_zip() -> Vec<u8> {
    let entries = many();
    let zip_entries: Vec<Entry<'_>> = entries
        .iter()
        .enumerate()
        .map(
            |(i, (name, data, mode))| match (name.ends_with('/'), *mode) {
                (true, _) if i % 2 == 0 => Entry::DirAt(name.as_bytes()),
                (true, _) => Entry::Dir(name.as_bytes()),
                (false, 0) if i % 3 == 0 => Entry::Stored(name.as_bytes(), data),
                (false, 0) => Entry::File(name.as_bytes(), data),
                (false, mode) => Entry::Mode(name.as_bytes(), data, mode),
            },
        )
        .collect();
    zip(&zip_entries)
}

/// What is under `dir`: each path, the length and a hash of what it holds or
/// leads to, its mode on Unix, and whether it has the archive's time. What
/// has none has the time it was written at, which differs from one run to the
/// next.
fn contents(dir: &Path) -> Vec<String> {
    let archive_time = UNIX_EPOCH + Duration::from_secs(MTIME as u64);
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
            let mode = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions());
            #[cfg(not(unix))]
            let mode = 0;
            // FNV-1a.
            let hash = data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
                (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
            });
            let dated = metadata.modified().unwrap() == archive_time;
            format!("{path} {} {hash:x} {mode:o} {dated}", data.len())
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
    options(|o| {
        o.threads = threads;
        o.links = Links::Inside;
        change(o);
    })
}

#[test]
fn what_is_written_is_the_same() {
    let data = many_zip();
    let entries = many();
    let mut first: Option<(String, Vec<String>)> = None;
    for threads in every_threads() {
        let scratch = Scratch::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let options = with_threads(threads, |o| {
            o.progress = Some(Arc::new(move |progress: &Progress| {
                record
                    .lock()
                    .unwrap()
                    .push((*progress, std::thread::current().id()));
            }));
        });
        let summary = extract(&data, &scratch.out(), &options).unwrap();
        let found = (told(&summary), contents(&scratch.out()));

        // Every file, whole.
        for (name, data, mode) in &entries {
            if name.ends_with('/') || *mode == 0o120_777 {
                continue;
            }
            assert_eq!(
                &std::fs::read(scratch.out().join(name)).unwrap(),
                data,
                "{name} with {threads:?}"
            );
        }
        // Told every piece and entry, never going back, up to the totals.
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
        let reporting: HashSet<_> = seen.iter().map(|(_, id)| *id).collect();
        match threads {
            Threads::One => assert_eq!(reporting.len(), 1),
            // Files of 70 kB and more, 36 of them: eight threads all
            // take some.
            Threads::Exactly(n) if n.get() == 8 => {
                assert!(reporting.len() > 1, "{threads:?}")
            }
            _ => {}
        }

        match &first {
            None => first = Some(found),
            Some(first) => {
                assert_eq!(first.0, found.0, "{threads:?}");
                assert_eq!(first.1, found.1, "{threads:?}");
            }
        }
    }
    let (summary, files) = first.unwrap();
    let dirs = entries
        .iter()
        .filter(|(name, ..)| name.ends_with('/'))
        .count();
    let links = entries
        .iter()
        .filter(|(.., mode)| *mode == 0o120_777)
        .count();
    let expected = format!(
        "{} files, {dirs} directories, {links} links",
        entries.len() - dirs - links
    );
    assert!(summary.starts_with(&expected), "{summary}");
    assert!(files.len() > 200);
}

/// The files damaged in [`zip_with_bad_crc`].
const BAD: [usize; 2] = [10, 25];

/// Fifty files, two stored with a byte of their data changed: their CRC-32
/// fails.
fn zip_with_bad_crc() -> Vec<u8> {
    let names: Vec<String> = (0..50).map(|i| format!("f{i:02}")).collect();
    let bodies: Vec<Vec<u8>> = (0..50).map(|i| text(i, 20_000 + 100 * i)).collect();
    let entries: Vec<Entry<'_>> = names
        .iter()
        .zip(&bodies)
        .enumerate()
        .map(|(i, (name, body))| {
            if BAD.contains(&i) {
                Entry::Stored(name.as_bytes(), body)
            } else {
                Entry::File(name.as_bytes(), body)
            }
        })
        .collect();
    let mut data = zip(&entries);
    for bad in BAD {
        let body = &bodies[bad];
        let at = data
            .windows(body.len())
            .position(|w| w == body.as_slice())
            .unwrap();
        data[at + 100] ^= 1;
    }
    data
}

#[test]
fn damaged_data_is_the_same() {
    let data = zip_with_bad_crc();
    for threads in every_threads() {
        // Stopping, the default: the error of one, the first with one thread,
        // and neither file left.
        let scratch = Scratch::new();
        let error = extract(&data, &scratch.out(), &with_threads(threads, |_| {})).unwrap_err();
        assert!(
            matches!(&error.kind, ErrorKind::Archive(e) if e.code() == hivepack::zip::ErrorCode::Crc),
            "{error}"
        );
        let index = error.index.unwrap() as usize;
        assert!(BAD.contains(&index), "{error}");
        if threads == Threads::One {
            assert_eq!(index, BAD[0]);
        }
        let written = listing(&scratch.out());
        for bad in BAD {
            assert!(!written.contains(&format!("f{bad:02}")), "{threads:?}");
        }
        // What was written is whole.
        for name in &written {
            let i: usize = name[1..].parse().unwrap();
            assert_eq!(
                std::fs::read(scratch.out().join(name)).unwrap(),
                text(i, 20_000 + 100 * i)
            );
        }
    }

    // Asked about, each once, and gone on from: the same summary and files.
    for how in [OnDamaged::Skip, OnDamaged::Keep] {
        let mut first = None;
        for threads in every_threads() {
            let scratch = Scratch::new();
            let asked = Arc::new(Mutex::new(Vec::new()));
            let record = Arc::clone(&asked);
            let options = with_threads(threads, |o| {
                o.on_damaged = Some(Arc::new(move |error: &Error| {
                    record.lock().unwrap().push(error.index.unwrap() as usize);
                    how
                }));
            });
            let summary = extract(&data, &scratch.out(), &options).unwrap();
            let mut asked = asked.lock().unwrap().clone();
            asked.sort_unstable();
            assert_eq!(asked, BAD);
            let damaged: Vec<_> = summary.damaged.iter().map(|d| d.error.index).collect();
            assert_eq!(damaged, BAD.map(|i| Some(i as u64)));
            let found = (told(&summary), contents(&scratch.out()));
            match &first {
                None => first = Some(found),
                Some(first) => assert_eq!(first, &found, "{how:?} with {threads:?}"),
            }
        }
    }
}

#[test]
fn the_limits_stop_it() {
    let data = many_zip();
    for threads in every_threads() {
        // The archive says too much: nothing is written.
        let scratch = Scratch::new();
        let options = with_threads(threads, |o| o.limits.max_total_size = 1_000_000);
        let error = extract(&data, &scratch.out(), &options).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::TotalTooLarge), "{error}");
        assert!(!scratch.out().exists());

        // A bomb among other files, past the ratio as it is written: removed,
        // and the others stopped.
        let zeros = vec![0u8; 4 << 20];
        let bodies: Vec<Vec<u8>> = (0..20).map(|i| text(i, 50_000)).collect();
        let names: Vec<String> = (0..20).map(|i| format!("f{i:02}")).collect();
        let mut entries: Vec<Entry<'_>> = names
            .iter()
            .zip(&bodies)
            .map(|(name, body)| Entry::File(name.as_bytes(), body))
            .collect();
        entries.insert(10, Entry::File(b"bomb", &zeros));
        let bomb = zip(&entries);
        let scratch = Scratch::new();
        let options = with_threads(threads, |o| o.limits.max_ratio = 100);
        let error = extract(&bomb, &scratch.out(), &options).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Ratio), "{error}");
        assert_eq!(error.index, Some(10));
        let written = listing(&scratch.out());
        assert!(!written.contains(&"bomb".to_string()), "{written:?}");
        for name in &written {
            let i: usize = name[1..].parse().unwrap();
            assert_eq!(std::fs::read(scratch.out().join(name)).unwrap(), bodies[i]);
        }
    }
}

#[test]
fn cancelling_stops_it() {
    let data = many_zip();
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
        let entries = many();
        let mut files = 0;
        for (name, body, _) in &entries {
            let at = scratch.out().join(name);
            if name.ends_with('/') || !at.is_file() {
                continue;
            }
            assert_eq!(
                &std::fs::read(&at).unwrap(),
                body,
                "{name} with {threads:?}"
            );
            files += 1;
        }
        assert!(files < entries.len() / 2, "{files} with {threads:?}");
    }
}

/// A sink is given the entries in order, on the caller's thread, whatever the
/// threads.
#[test]
fn a_sink_is_given_the_same() {
    #[derive(Default)]
    struct Names(Vec<String>);
    impl hivepack::extract::Sink for Names {
        fn directory(&mut self, entry: &hivepack::extract::Entry<'_>) -> std::io::Result<()> {
            self.0.push(entry.path.join("/"));
            Ok(())
        }
        fn start_file(&mut self, entry: &hivepack::extract::Entry<'_>) -> std::io::Result<()> {
            self.0.push(entry.path.join("/"));
            Ok(())
        }
        fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
            self.0.push(data.len().to_string());
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
            self.0.push(format!("{} -> {target}", entry.path.join("/")));
            Ok(())
        }
        fn hard_link(
            &mut self,
            _: &hivepack::extract::Entry<'_>,
            _: &[String],
        ) -> std::io::Result<()> {
            Ok(())
        }
    }
    let data = many_zip();
    let archive = Archive::open(data.as_slice(), OpenFlags::CHECKCONS).unwrap();
    let mut first = Names::default();
    extract_zip_to(&archive, &mut first, &with_threads(Threads::One, |_| {})).unwrap();
    let mut eight = Names::default();
    let threads = Threads::Exactly(NonZeroU32::new(8).unwrap());
    extract_zip_to(&archive, &mut eight, &with_threads(threads, |_| {})).unwrap();
    assert_eq!(first.0, eight.0);
}
