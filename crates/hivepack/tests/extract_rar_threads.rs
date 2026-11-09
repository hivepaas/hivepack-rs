//! Extracting a RAR archive with `Options::threads`: an archive that is not
//! solid has its files written several at once, each thread going through the
//! archive itself. What is written, and the summary, are the same as with one
//! thread; damaged data and the limits stop it, or are gone on from, as they do
//! with one; and the threads are lowered to fit `Options::memory_limit`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "threads_support/mod.rs"]
mod threads_support;

#[path = "extract_support/mod.rs"]
mod support;

#[path = "rar_support/patch.rs"]
#[allow(dead_code)]
mod patch;

use std::collections::HashSet;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hivepack::Threads;
use hivepack::extract::{
    Error, ErrorKind, Links, OnDamaged, Options, Progress, Summary, extract_rar,
};
use hivepack::rar::Archive;
use patch::{Entry, with_entries};
use support::{Scratch, listing, options};

const SYMLINK: u64 = 1;
const HARD_LINK: u64 = 4;
const FILE_COPY: u64 = 5;

/// One thread, two, eight, and as many as the machine runs.
fn every_threads() -> Vec<Threads> {
    threads_support::chosen([
        Threads::One,
        Threads::Exactly(NonZeroU32::new(2).unwrap()),
        Threads::Exactly(NonZeroU32::new(8).unwrap()),
        Threads::Auto,
    ])
}

fn extract(data: &[u8], out: &Path, options: &Options) -> Result<Summary, Error> {
    extract_rar(
        |password| Archive::open_with_password(data, false, password),
        out,
        options,
    )
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

/// A name, its data, and the kind of redirection it is, with its target.
type Named = (String, Vec<u8>, Option<(u64, String)>);

/// Names and data: directories, files small and empty, two large ones the
/// threads take first, the largest last, and what has no data of its own: a
/// hard link, a file copy, and a link, after the files they are of.
fn many() -> Vec<Named> {
    let mut entries = Vec::new();
    for d in 0..4 {
        entries.push((format!("d{d}"), Vec::new(), None));
        for f in 0..20 {
            let n = d * 100 + f;
            let data = match f % 5 {
                0 => Vec::new(),
                1 => text(n, 3 + n % 40),
                _ => text(n, 900 + 41 * n),
            };
            entries.push((format!("d{d}/f{f}.txt"), data, None));
        }
    }
    entries.push(("big/one".into(), text(1, 300_000), None));
    entries.push((
        "d0/hard".into(),
        Vec::new(),
        Some((HARD_LINK, "d0/f2.txt".into())),
    ));
    entries.push((
        "d1/copy".into(),
        Vec::new(),
        Some((FILE_COPY, "d1/f3.txt".into())),
    ));
    entries.push((
        "d2/link".into(),
        Vec::new(),
        Some((SYMLINK, "f4.txt".into())),
    ));
    entries.push(("big/two".into(), text(2, 600_000), None));
    entries
}

fn many_rar() -> Vec<u8> {
    let entries = many();
    let rar: Vec<Entry<'_>> = entries
        .iter()
        .map(|(name, data, redirect)| match redirect {
            Some((kind, target)) => Entry::redirect(name.as_bytes(), *kind, target.as_bytes()),
            None if !name.contains('/') || name == "big" => Entry::dir(name.as_bytes()),
            None => Entry::file(name.as_bytes(), data),
        })
        .collect();
    with_entries(&rar)
}

/// What is under `dir`: each path, the length and a hash of what it holds or
/// leads to, and its mode on Unix.
fn contents(dir: &Path) -> Vec<String> {
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
            format!("{path} {} {hash:x} {mode:o}", data.len())
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

/// Extracts `data` with each of [`every_threads`] and `change`: the summary
/// and what is written are those of one thread, and the threads that told the
/// progress, for each.
fn the_same(label: &str, data: &[u8], change: impl Fn(&mut Options)) -> Vec<(Threads, usize)> {
    let mut first: Option<(String, Vec<String>)> = None;
    let mut reporting = Vec::new();
    for threads in every_threads() {
        let scratch = Scratch::new();
        let seen = Arc::new(Mutex::new(HashSet::new()));
        let record = Arc::clone(&seen);
        let options = with_threads(threads, |o| {
            change(o);
            o.progress = Some(Arc::new(move |_: &Progress| {
                record.lock().unwrap().insert(std::thread::current().id());
            }));
        });
        let summary = extract(data, &scratch.out(), &options)
            .unwrap_or_else(|e| panic!("{label} with {threads:?}: {e}"));
        let found = (told(&summary), contents(&scratch.out()));
        match &first {
            None => first = Some(found),
            Some(first) => assert_eq!(&found, first, "{label} with {threads:?}"),
        }
        reporting.push((threads, seen.lock().unwrap().len()));
    }
    reporting
}

/// How many threads wrote with the most threads given: eight, or two under
/// emulation ([`threads_support::chosen`]).
fn most(reporting: &[(Threads, usize)]) -> usize {
    reporting
        .iter()
        .find(|(t, _)| *t == Threads::Exactly(NonZeroU32::new(8).unwrap()))
        .or(reporting.last())
        .map_or(0, |(_, n)| *n)
}

#[test]
fn what_is_written_is_the_same() {
    let data = many_rar();
    let reporting = the_same("many", &data, |_| {});
    // Several threads wrote, where asked to: the most there are.
    assert_eq!(reporting[0].1, 1);
    assert!(most(&reporting) > 1, "{reporting:?}");
    let scratch = Scratch::new();
    let options = with_threads(Threads::Exactly(NonZeroU32::new(4).unwrap()), |_| {});
    extract(&data, &scratch.out(), &options).unwrap();
    for (name, bytes, redirect) in many() {
        let at = scratch.out().join(&name);
        match redirect {
            None if at.is_dir() => {}
            None => assert_eq!(std::fs::read(&at).unwrap(), bytes, "{name}"),
            Some((SYMLINK, _)) if !cfg!(unix) => {}
            Some((SYMLINK, target)) => {
                assert_eq!(std::fs::read_link(&at).unwrap(), PathBuf::from(target));
            }
            Some((_, target)) => {
                let of = scratch.out().join(target);
                assert_eq!(
                    std::fs::read(&at).unwrap(),
                    std::fs::read(of).unwrap(),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn links_as_files_and_picked_entries_are_the_same() {
    let data = many_rar();
    the_same("as files", &data, |o| o.links = Links::AsFile);
    the_same("picked", &data, |o| {
        o.select = Some(Arc::new(|path: &[String]| {
            path.first()
                .is_some_and(|first| first == "d1" || first == "big")
        }));
    });
}

/// The repository's archives: RAR 4 and 5, LZ and PPMd, with a password,
/// and solid, which one thread reads. RAR 5's have a QuickOpen record, which
/// a thread going to a large file's header reads through.
#[test]
fn real_archives_are_the_same() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rar");
    let mut read = 0;
    for name in [
        "rar4-m1.rar",
        "rar4-m3.rar",
        "rar4-m3-ppmd.rar",
        "rar4-m3-password.rar",
        "rar4-m5-solid.rar",
        "rar5-m1.rar",
        "rar5-m3.rar",
        "rar5-m3-password.rar",
        "rar5-m3-solid.rar",
        "rar5-m5.rar",
    ] {
        let data = std::fs::read(root.join(name)).unwrap();
        let reporting = the_same(name, &data, |o| {
            o.password = Some(b"hivepack".to_vec());
            o.limits.max_ratio = u64::MAX;
        });
        let several = most(&reporting) > 1;
        assert_eq!(several, !name.contains("solid"), "{name}: {reporting:?}");
        read += 1;
    }
    assert_eq!(read, 10);
}

#[test]
fn the_threads_fit_the_memory_limit() {
    let data = many_rar();
    let eight = Threads::Exactly(NonZeroU32::new(8).unwrap());
    // Stored data takes a thread its buffers, about 5 MiB: two fit 11 MiB.
    for (limit, most) in [(1, 1), (11 << 20, 2), (u64::MAX, 8)] {
        let scratch = Scratch::new();
        let seen = Arc::new(Mutex::new(HashSet::new()));
        let record = Arc::clone(&seen);
        let options = with_threads(eight, |o| {
            o.memory_limit = Some(limit);
            o.progress = Some(Arc::new(move |_: &Progress| {
                record.lock().unwrap().insert(std::thread::current().id());
            }));
        });
        extract(&data, &scratch.out(), &options).unwrap();
        let reporting = seen.lock().unwrap().len();
        // The caller's thread tells the directories and the links.
        assert!(reporting <= most + 1, "{limit}: {reporting}");
        if most == 1 {
            assert_eq!(reporting, 1, "{limit}");
        }
    }
}

#[cfg(feature = "memory")]
#[test]
fn the_threads_are_held_from_the_budget() {
    use hivepack::memory::Budget;
    let data = many_rar();
    let budget = Budget::new(11 << 20);
    let during = Arc::new(Mutex::new(0u64));
    let record = Arc::clone(&during);
    let held = budget.clone();
    let options = with_threads(Threads::Exactly(NonZeroU32::new(8).unwrap()), |o| {
        o.memory_budget = Some(budget.clone());
        o.progress = Some(Arc::new(move |_: &Progress| {
            let mut most = record.lock().unwrap();
            *most = (*most).max(held.held());
        }));
    });
    let scratch = Scratch::new();
    extract(&data, &scratch.out(), &options).unwrap();
    let most = *during.lock().unwrap();
    assert!(most > 0 && most <= 11 << 20, "{most}");
    assert_eq!(budget.held(), 0);
}

#[test]
fn damage_is_gone_on_from_as_with_one_thread() {
    let mut entries = Vec::new();
    let datas: Vec<Vec<u8>> = (0..30).map(|n| text(n, 2000 + n)).collect();
    let names: Vec<String> = (0..30).map(|n| format!("f{n}")).collect();
    for n in 0..30 {
        entries.push(Entry {
            bad_crc: n % 7 == 3,
            ..Entry::file(names[n].as_bytes(), &datas[n])
        });
    }
    let data = with_entries(&entries);
    for how in [OnDamaged::Skip, OnDamaged::Keep] {
        the_same(&format!("{how:?}"), &data, |o| {
            o.on_damaged = Some(Arc::new(move |_: &Error| how));
        });
    }
    // Without on_damaged, it stops: on the first file, with one thread.
    for threads in every_threads() {
        let scratch = Scratch::new();
        let error = extract(&data, &scratch.out(), &with_threads(threads, |_| {})).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::RarEntry(_)),
            "{threads:?}: {error}"
        );
        assert!(!scratch.out().join(&names[3]).exists(), "{threads:?}");
    }
}

#[test]
fn the_total_limit_stops_the_threads() {
    let data = many_rar();
    for threads in every_threads() {
        let scratch = Scratch::new();
        let options = with_threads(threads, |o| o.limits.max_total_size = 500_000);
        let error = extract(&data, &scratch.out(), &options).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::TotalTooLarge),
            "{threads:?}: {error}"
        );
    }
}
