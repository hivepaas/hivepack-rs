//! Extracting a 7z archive with `Options::threads`: its folders, the solid
//! blocks or the files of an archive that is not solid, decoded several at
//! once, each by a thread that writes its files. What is written, and the
//! summary, are the same as with one thread, whatever the methods; damaged
//! data, a wrong password and the limits stop it, or are gone on from, as
//! they do with one; and the threads are lowered to fit
//! `Options::memory_limit`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::collections::HashSet;
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

use hivepack::Threads;
use hivepack::extract::{
    Cancel, Error, ErrorKind, Links, OnDamaged, OnRefused, Options, Progress, Summary, extract_7z,
};
use hivepack::sevenz::{Archive, Lzma2Blocks, Method, NewEntry, WriteOptions, Writer};
use support::{Scratch, listing, options};

/// One thread, two, eight, and as many as the machine runs.
fn every_threads() -> [Threads; 4] {
    [Threads::One, Threads::of(2), Threads::of(8), Threads::Auto]
}

/// What goes in an archive.
enum Put {
    Dir(String),
    File(String, Vec<u8>, Method),
    /// A symbolic link, its target.
    Link(String, String),
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

/// The methods the files take turns at.
const METHODS: [Method; 5] = [
    Method::Lzma2 { preset: 1 },
    Method::Lzma { preset: 1 },
    Method::BZip2 { level: 1 },
    Method::Deflate { level: 6 },
    Method::Copy,
];

/// Directories, files small, large and empty, of every method, and links after
/// the files they lead to.
fn many() -> Vec<Put> {
    let mut puts = Vec::new();
    for d in 0..3 {
        puts.push(Put::Dir(format!("d{d}")));
        for f in 0..12 {
            let n = d * 100 + f;
            let data = match f % 4 {
                0 => Vec::new(),
                1 => text(n, 3 + n % 40),
                _ => text(n, 900 + 37 * n),
            };
            puts.push(Put::File(
                format!("d{d}/f{f}.txt"),
                data,
                METHODS[n % METHODS.len()],
            ));
        }
    }
    puts.push(Put::File(
        "big/one".into(),
        text(1, 200_000),
        Method::Lzma2 { preset: 1 },
    ));
    puts.push(Put::Link("d1/link".into(), "f2.txt".into()));
    puts.push(Put::Link("d2/up".into(), "../d0".into()));
    puts.push(Put::File("big/two".into(), text(2, 300_000), Method::Copy));
    puts
}

/// The archive of `puts`, with `options`: a folder a file, unless it says
/// otherwise.
fn archive(puts: &[Put], options: WriteOptions) -> Vec<u8> {
    let next = std::sync::atomic::AtomicU8::new(1);
    let options = WriteOptions {
        random_source: Some(Arc::new(move |bytes: &mut [u8]| {
            for b in bytes {
                *b = next.fetch_add(13, std::sync::atomic::Ordering::Relaxed);
            }
            Ok(())
        })),
        ..options
    };
    let mut w = Writer::with_options(Cursor::new(Vec::new()), options).unwrap();
    for put in puts {
        match put {
            Put::Dir(name) => w.add_directory(NewEntry::new(name)).unwrap(),
            Put::File(name, data, method) => {
                w.set_method(*method).unwrap();
                w.add_file(NewEntry::new(name), &mut &data[..]).unwrap();
            }
            Put::Link(name, target) => {
                w.set_method(Method::Copy).unwrap();
                let mut entry = NewEntry::new(name);
                entry.attributes = Some(0x8000 | (0o120_777 << 16));
                w.add_file(entry, &mut target.as_bytes()).unwrap();
            }
        }
    }
    w.finish().unwrap().into_inner()
}

/// A folder a file.
fn apart() -> WriteOptions {
    WriteOptions {
        solid_block_size: None,
        ..WriteOptions::default()
    }
}

fn extract(data: &[u8], out: &Path, options: &Options) -> Result<Summary, Error> {
    let mut archive = Archive::open(Cursor::new(data)).unwrap();
    extract_7z(&mut archive, out, options)
}

/// What is under `dir`: each path, the length and a hash of what it holds or
/// leads to.
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
            // FNV-1a.
            let hash = data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
                (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
            });
            format!("{path} {} {hash:x}", data.len())
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
        "{} files, {} directories, {} links, {} bytes, skipped {skipped:?}, damaged {damaged:?}",
        summary.files, summary.directories, summary.links, summary.bytes,
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
/// and what is written are those of one thread. The threads that told the
/// progress, for each, and whether the progress went on, one call at a time.
fn the_same(label: &str, data: &[u8], change: impl Fn(&mut Options)) -> Vec<usize> {
    let mut first: Option<(String, Vec<String>)> = None;
    let mut reporting = Vec::new();
    for threads in every_threads() {
        let scratch = Scratch::new();
        let seen = Arc::new(Mutex::new((HashSet::new(), 0u64, 0u64)));
        let record = Arc::clone(&seen);
        let options = with_threads(threads, |o| {
            change(o);
            o.progress = Some(Arc::new(move |progress: &Progress| {
                let mut seen = record.lock().unwrap();
                seen.0.insert(std::thread::current().id());
                assert!(progress.entries >= seen.1 && progress.bytes >= seen.2);
                (seen.1, seen.2) = (progress.entries, progress.bytes);
            }));
        });
        let summary = extract(data, &scratch.out(), &options)
            .unwrap_or_else(|e| panic!("{label} with {threads:?}: {e}"));
        let found = (told(&summary), contents(&scratch.out()));
        match &first {
            None => first = Some(found),
            Some(first) => assert_eq!(&found, first, "{label} with {threads:?}"),
        }
        reporting.push(seen.lock().unwrap().0.len());
    }
    reporting
}

#[test]
fn what_is_written_is_the_same() {
    let puts = many();
    let data = archive(&puts, apart());
    let reporting = the_same("apart", &data, |_| {});
    // Several threads wrote, where asked to.
    assert_eq!(reporting[0], 1);
    assert!(reporting[2] > 1, "{reporting:?}");
    let scratch = Scratch::new();
    extract(&data, &scratch.out(), &with_threads(Threads::of(4), |_| {})).unwrap();
    for put in &puts {
        match put {
            Put::Dir(name) => assert!(scratch.out().join(name).is_dir()),
            Put::File(name, bytes, _) => {
                assert_eq!(&std::fs::read(scratch.out().join(name)).unwrap(), bytes);
            }
            Put::Link(..) if !cfg!(unix) => {}
            Put::Link(name, target) => {
                let read = std::fs::read_link(scratch.out().join(name)).unwrap();
                assert_eq!(read.to_str(), Some(target.as_str()));
            }
        }
    }
    the_same("as files", &data, |o| o.links = Links::AsFile);
    the_same("picked", &data, |o| {
        o.select = Some(Arc::new(|path: &[String]| {
            path.first().is_some_and(|first| first != "d1")
        }));
    });
}

/// Solid blocks of a few files, LZMA2 in blocks within them too: the threads
/// left over decode those.
#[test]
fn solid_blocks_are_the_same() {
    let data = archive(
        &many(),
        WriteOptions {
            solid_block_size: Some(20_000),
            lzma2_blocks: Lzma2Blocks::Size(1 << 16),
            ..WriteOptions::default()
        },
    );
    assert!(Archive::open(Cursor::new(&data)).unwrap().folders() > 4);
    let reporting = the_same("solid", &data, |_| {});
    assert!(reporting[2] > 1, "{reporting:?}");
    // With a password, the key made once for all the threads.
    let data = archive(
        &many(),
        WriteOptions {
            solid_block_size: Some(20_000),
            password: Some("secret".into()),
            key_cycles: 4,
            ..WriteOptions::default()
        },
    );
    the_same("encrypted", &data, |o| {
        o.password = Some(b"secret".to_vec())
    });
}

/// The repository's archives, which 7-Zip made: LZMA2 solid, Deflate and
/// stored a folder a file, BCJ2, AES, links.
#[test]
fn real_archives_are_the_same() {
    let root = support::repository().join("testdata/7z");
    for name in [
        "plain.7z",
        "deflate.7z",
        "stored.7z",
        "bcj2.7z",
        "encrypted.7z",
        "links.7z",
    ] {
        let data = std::fs::read(root.join(name)).unwrap();
        the_same(name, &data, |o| {
            o.password = Some(b"secret".to_vec());
            // A link of `links.7z` leads outside.
            o.on_refused = OnRefused::Skip;
        });
    }
}

/// Where folder `folder`'s packed data starts in `data`.
fn packed_at(data: &[u8], folder: usize) -> usize {
    let archive = Archive::open(Cursor::new(data)).unwrap();
    32 + (0..folder)
        .map(|f| archive.folder_packed_size(f) as usize)
        .sum::<usize>()
}

#[test]
fn damage_is_gone_on_from_as_with_one_thread() {
    let puts: Vec<Put> = (0..24)
        .map(|n| {
            Put::File(
                format!("f{n:02}"),
                text(n, 3000 + 10 * n),
                METHODS[n % METHODS.len()],
            )
        })
        .collect();
    let mut data = archive(&puts, apart());
    for folder in [3, 4, 10, 17, 19] {
        let at = packed_at(&data, folder) + 40;
        data[at] ^= 0x55;
    }
    for how in [OnDamaged::Skip, OnDamaged::Keep] {
        the_same(&format!("{how:?}"), &data, |o| {
            o.on_damaged = Some(Arc::new(move |_: &Error| how));
        });
    }
    let scratch = Scratch::new();
    let options = with_threads(Threads::of(4), |o| {
        o.on_damaged = Some(Arc::new(|_: &Error| OnDamaged::Skip));
    });
    let summary = extract(&data, &scratch.out(), &options).unwrap();
    let damaged: Vec<_> = summary.damaged.iter().map(|d| d.error.index).collect();
    assert_eq!(damaged, [Some(3), Some(4), Some(10), Some(17), Some(19)]);
    // Without on_damaged, it stops, and leaves no damaged file.
    for threads in every_threads() {
        let scratch = Scratch::new();
        let error = extract(&data, &scratch.out(), &with_threads(threads, |_| {})).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::SevenZip(_)),
            "{threads:?}: {error}"
        );
        for damaged in ["f03", "f04", "f10", "f17", "f19"] {
            assert!(!scratch.out().join(damaged).exists(), "{threads:?}");
        }
    }
}

#[test]
fn a_wrong_password_stops_every_thread() {
    let data = archive(
        &many(),
        WriteOptions {
            solid_block_size: None,
            password: Some("secret".into()),
            key_cycles: 4,
            ..WriteOptions::default()
        },
    );
    for threads in every_threads() {
        let scratch = Scratch::new();
        let options = with_threads(threads, |o| o.password = Some(b"wrong".to_vec()));
        let error = extract(&data, &scratch.out(), &options).unwrap_err();
        assert!(
            matches!(
                error.kind,
                ErrorKind::SevenZip(hivepack::sevenz::Error::WrongPassword)
            ),
            "{threads:?}: {error}"
        );
        let files: Vec<_> = listing(&scratch.out())
            .into_iter()
            .filter(|path| !path.ends_with('/'))
            .collect();
        // Only the empty files, made before the folders.
        for file in &files {
            let len = std::fs::metadata(scratch.out().join(file)).unwrap().len();
            assert_eq!(len, 0, "{threads:?}: {file}");
        }
    }
}

#[test]
fn the_limits_and_a_cancel_stop_the_threads() {
    let data = archive(&many(), apart());
    for threads in every_threads() {
        let scratch = Scratch::new();
        let options = with_threads(threads, |o| o.limits.max_total_size = 300_000);
        let error = extract(&data, &scratch.out(), &options).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::TotalTooLarge),
            "{threads:?}: {error}"
        );

        let scratch = Scratch::new();
        let cancel = Cancel::new();
        let stop = cancel.clone();
        let options = with_threads(threads, |o| {
            o.cancel = Some(cancel.clone());
            o.progress = Some(Arc::new(move |progress: &Progress| {
                if progress.entries > 10 {
                    stop.cancel();
                }
            }));
        });
        let error = extract(&data, &scratch.out(), &options).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::Cancelled),
            "{threads:?}: {error}"
        );
    }
}

/// The threads that tell the progress of `data` extracted in eight threads
/// with `change`.
fn reporting(data: &[u8], change: impl FnOnce(&mut Options)) -> usize {
    let scratch = Scratch::new();
    let seen = Arc::new(Mutex::new(HashSet::new()));
    let record = Arc::clone(&seen);
    let options = with_threads(Threads::of(8), |o| {
        change(o);
        o.progress = Some(Arc::new(move |_: &Progress| {
            record.lock().unwrap().insert(std::thread::current().id());
        }));
    });
    extract(data, &scratch.out(), &options).unwrap();
    seen.lock().unwrap().len()
}

#[test]
fn the_threads_fit_the_memory_limit() {
    // Stored folders: a thread takes their buffers, 1.125 MiB.
    let puts: Vec<Put> = (0..12)
        .map(|n| Put::File(format!("f{n:02}"), text(n, 20_000), Method::Copy))
        .collect();
    let data = archive(&puts, apart());
    for (limit, most) in [(1, 1), (5 << 19, 2), (u64::MAX, 8)] {
        let reporting = reporting(&data, |o| o.memory_limit = Some(limit));
        // The caller's thread tells the directories.
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
    let data = archive(&many(), apart());
    // BZip2's folders count 5.1 MiB each: two fit.
    let budget = Budget::new(12 << 20);
    let during = Arc::new(Mutex::new(0u64));
    let record = Arc::clone(&during);
    let held = budget.clone();
    let options = with_threads(Threads::of(8), |o| {
        o.memory_budget = Some(budget.clone());
        o.progress = Some(Arc::new(move |_: &Progress| {
            let mut most = record.lock().unwrap();
            *most = (*most).max(held.held());
        }));
    });
    let scratch = Scratch::new();
    extract(&data, &scratch.out(), &options).unwrap();
    let most = *during.lock().unwrap();
    assert!(most > 0 && most <= 12 << 20, "{most}");
    assert_eq!(budget.held(), 0);
}
