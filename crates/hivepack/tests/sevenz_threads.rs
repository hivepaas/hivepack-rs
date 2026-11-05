//! LZMA2 in blocks, each starting with a reset of the dictionary, compressed
//! and decompressed in threads: what is written is the same whatever the
//! threads, it reads back here with one thread or many, and in `7zz` and the
//! LZMA SDK's decoder where `scripts/testdata.py` built them; and what 7-Zip
//! writes in threads, or anything without blocks, reads the same with threads
//! as without, damaged or not.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "sevenz_support/mod.rs"]
mod support;

use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use hivepack::Threads;
use hivepack::sevenz::{
    Archive, Error, Filter, Lzma2Blocks, Method, NewEntry, Options, WriteOptions, Writer,
};
use support::{Oracle, Rng, scratch, seven_zip};

/// The threads each test is run with.
fn threads() -> [Threads; 4] {
    [Threads::One, Threads::of(2), Threads::of(8), Threads::Auto]
}

/// A file's name and data, or a directory's name.
type Item = (String, Option<Vec<u8>>);

/// `count` files and a few directories, some empty, the files of up to
/// `max` bytes of several kinds.
fn items(rng: &mut Rng, count: usize, max: u64) -> Vec<Item> {
    (0..count)
        .map(|i| {
            let name = format!("dir{}/file {i}.dat", i % 3);
            match rng.below(10) {
                0 => (format!("dir{i}"), None),
                1 => (name, Some(Vec::new())),
                _ => {
                    let size = rng.below(max) as usize;
                    (name, Some(support::input(rng, size)))
                }
            }
        })
        .collect()
}

/// The same salts and IVs each time.
fn counting_source() -> hivepack::sevenz::RandomSource {
    let next = std::sync::atomic::AtomicU8::new(1);
    Arc::new(move |bytes: &mut [u8]| {
        for b in bytes {
            *b = next.fetch_add(13, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    })
}

/// The archive of `items`, each file's data given in pieces of random sizes.
fn write(options: &WriteOptions, items: &[Item], seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let options = WriteOptions {
        random_source: Some(counting_source()),
        ..options.clone()
    };
    let mut w = Writer::with_options(Cursor::new(Vec::new()), options).unwrap();
    for (name, data) in items {
        match data {
            None => w.add_directory(NewEntry::new(name)).unwrap(),
            Some(data) => {
                w.start_file(NewEntry::new(name)).unwrap();
                let mut rest = &data[..];
                while !rest.is_empty() {
                    let n = (1 + rng.below(100_000) as usize).min(rest.len());
                    w.write_all(&rest[..n]).unwrap();
                    rest = &rest[n..];
                }
            }
        }
    }
    w.finish().unwrap().into_inner()
}

/// What reading an archive gives: each entry's name and the size and hash of
/// its data, or the error its data failed with, the files of its folder after
/// it skipped as extraction skips them; or the error opening or moving on
/// stops at.
#[derive(Debug, PartialEq, Eq)]
enum Read_ {
    Entry(String, Result<(usize, u64), Error>),
    Skipped(usize),
    Stopped(Error),
}

fn summed(data: &[u8]) -> (usize, u64) {
    (data.len(), support::fnv64(data))
}

/// `got` is `want`, or the first entry where they differ is shown.
fn same(got: &[Read_], want: &[Read_], what: &str) {
    if let Some(at) = (0..got.len().max(want.len())).find(|&i| got.get(i) != want.get(i)) {
        panic!(
            "{what}: at {at} of {} and {}: {:?}, not {:?}",
            got.len(),
            want.len(),
            got.get(at),
            want.get(at)
        );
    }
}

fn sevenz_error(e: &std::io::Error) -> Error {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<Error>())
        .copied()
        .unwrap_or(Error::Read)
}

/// Everything `Archive::files` reads of `archive`, with `threads`.
fn read_all(archive: &[u8], password: Option<&str>, threads: Threads) -> Vec<Read_> {
    let open = Options {
        password: password.map(str::to_string),
        ..Options::default()
    };
    let mut got = Vec::new();
    let mut a = match Archive::open_with(Cursor::new(archive), &open) {
        Ok(a) => a,
        Err(e) => return vec![Read_::Stopped(e)],
    };
    a.set_threads(threads);
    let mut files = a.files();
    loop {
        let entry = match files.next() {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                got.push(Read_::Stopped(e));
                break;
            }
        };
        let mut data = Vec::new();
        match files.read_to_end(&mut data) {
            Ok(_) => got.push(Read_::Entry(entry.name, Ok(summed(&data)))),
            Err(e) => {
                got.push(Read_::Entry(entry.name, Err(sevenz_error(&e))));
                let skipped = files.skip_folder();
                got.push(Read_::Skipped(skipped.len()));
            }
        }
    }
    got
}

/// What `items` read as.
fn as_read(items: &[Item]) -> Vec<Read_> {
    items
        .iter()
        .map(|(name, data)| Read_::Entry(name.clone(), Ok(summed(data.as_deref().unwrap_or(&[])))))
        .collect()
}

/// The decoded size of each chunk of the LZMA2 stream at the start of
/// `packed`, and whether it resets the dictionary.
fn chunks(packed: &[u8]) -> Vec<(u64, bool)> {
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let control = packed[at];
        let be = |i: usize| u64::from(packed[at + i]);
        let (len, size) = match control {
            0x00 => return out,
            0x01 | 0x02 => {
                let size = (be(1) << 8 | be(2)) + 1;
                (3 + size, size)
            }
            0x80..=0xFF => {
                let header = if control >= 0xC0 { 6 } else { 5 };
                let size = ((u64::from(control & 0x1F) << 16) | be(1) << 8 | be(2)) + 1;
                (header + (be(3) << 8 | be(4)) + 1, size)
            }
            _ => panic!("no chunk at {at}: {control:#x}"),
        };
        out.push((size, control == 0x01 || control >= 0xE0));
        at += len as usize;
    }
}

/// Where in the decoded stream the dictionary is reset.
fn resets(packed: &[u8]) -> Vec<u64> {
    let mut at = 0;
    let mut found = Vec::new();
    for (size, reset) in chunks(packed) {
        if reset {
            found.push(at);
        }
        at += size;
    }
    found
}

fn options(blocks: Lzma2Blocks) -> WriteOptions {
    WriteOptions {
        method: Method::Lzma2 { preset: 1 },
        lzma2_blocks: blocks,
        ..WriteOptions::default()
    }
}

#[test]
fn the_same_archive_whatever_the_threads() {
    let mut rng = Rng(0x7ead_5001);
    let list = items(&mut rng, 40, 300_000);
    let mut kinds = Vec::new();
    for filter in [Filter::None, Filter::X86, Filter::Delta(4)] {
        for blocks in [Lzma2Blocks::Size(1 << 16), Lzma2Blocks::Auto] {
            kinds.push(WriteOptions {
                filter,
                ..options(blocks)
            });
        }
    }
    kinds.push(WriteOptions {
        password: Some("pass wörd".into()),
        encrypt_headers: true,
        key_cycles: 4,
        ..options(Lzma2Blocks::Size(100_000))
    });
    kinds.push(WriteOptions {
        solid_block_size: None,
        ..options(Lzma2Blocks::Size(1 << 12))
    });
    for kind in kinds {
        let what = format!("{kind:?}");
        let one = write(&kind, &list, 1);
        // The pieces data comes in change nothing either.
        for (threads, seed) in threads().into_iter().zip(2..) {
            let other = write(
                &WriteOptions {
                    threads,
                    ..kind.clone()
                },
                &list,
                seed,
            );
            assert!(one == other, "{what}: {threads:?}");
        }
    }
    // Without blocks, threads change nothing: one stream, as before.
    let plain = WriteOptions::default();
    let with = WriteOptions {
        threads: Threads::of(8),
        ..WriteOptions::default()
    };
    assert!(write(&plain, &list, 1) == write(&with, &list, 1));
}

#[test]
fn each_block_starts_with_a_reset() {
    let mut rng = Rng(0x7ead_5002);
    // Files crossing the blocks' ends, and one larger than several blocks.
    let mut list = items(&mut rng, 30, 150_000);
    list.push(("big".into(), Some(support::input(&mut rng, 900_000))));
    let total: u64 = list
        .iter()
        .map(|(_, d)| d.as_ref().map_or(0, Vec::len) as u64)
        .sum();
    for (blocks, size) in [
        (Lzma2Blocks::Size(1 << 16), 1u64 << 16),
        (Lzma2Blocks::Size(100_000), 100_000),
        // Preset 1 has a dictionary of 1 MiB: blocks of 4.
        (Lzma2Blocks::Auto, 4 << 20),
    ] {
        let archive = write(&options(blocks), &list, 3);
        let a = Archive::open(Cursor::new(&archive)).unwrap();
        assert_eq!(a.folders(), 1);
        assert_eq!(a.folder_size(0), total);
        let packed = &archive[32..32 + a.folder_packed_size(0) as usize];
        let want: Vec<u64> = (0..total.div_ceil(size)).map(|i| i * size).collect();
        assert_eq!(resets(packed), want, "{blocks:?}");
        // One stream, ended once.
        assert_eq!(chunks(packed).iter().map(|c| c.0).sum::<u64>(), total);
        assert_eq!(packed.last(), Some(&0));
    }
}

#[test]
fn block_sizes_out_of_range() {
    for size in [0, 4095, (1 << 30) + 1, u64::MAX] {
        let options = options(Lzma2Blocks::Size(size));
        assert!(matches!(
            Writer::with_options(Cursor::new(Vec::new()), options),
            Err(Error::Param)
        ));
    }
    let mut w = Writer::with_options(
        Cursor::new(Vec::new()),
        WriteOptions {
            method: Method::Copy,
            lzma2_blocks: Lzma2Blocks::Size(1),
            ..WriteOptions::default()
        },
    )
    .expect("blocks are for LZMA2 alone");
    assert_eq!(w.set_method(Method::Lzma2 { preset: 1 }), Err(Error::Param));
}

/// A dictionary no larger than a block, in the header too.
#[test]
fn the_dictionary_of_small_blocks() {
    let data = support::input(&mut Rng(9), 200_000);
    let list = vec![("f".to_string(), Some(data))];
    let small = write(&options(Lzma2Blocks::Size(1 << 16)), &list, 1);
    let auto = write(&options(Lzma2Blocks::Auto), &list, 1);
    // The coder's properties, `21` and one byte: 2^16 is 8, and 1 MiB 16.
    let prop = |archive: &[u8]| {
        let mut a = Archive::open(Cursor::new(archive)).unwrap();
        assert_eq!(a.files().next().unwrap().unwrap().name, "f");
        let header = &archive[32 + a.folder_packed_size(0) as usize..];
        let at = header
            .windows(3)
            .position(|w| w[0] == 0x21 && w[1] == 1)
            .unwrap_or_else(|| {
                // A compressed header: read its coders by decoding it.
                panic!("no LZMA2 coder in {header:x?}")
            });
        header[at + 2]
    };
    let raw = |options: WriteOptions| WriteOptions {
        compress_headers: false,
        ..options
    };
    assert_eq!(
        prop(&write(&raw(options(Lzma2Blocks::Size(1 << 16))), &list, 1)),
        8
    );
    assert_eq!(prop(&write(&raw(options(Lzma2Blocks::Auto)), &list, 1)), 16);
    assert_eq!(read_all(&small, None, Threads::of(4)), as_read(&list));
    assert_eq!(read_all(&auto, None, Threads::of(4)), as_read(&list));
}

/// `7zz` tests it without a warning and extracts what was written, and the
/// SDK's decoder decodes it.
fn check_outside(
    archive: &[u8],
    items: &[Item],
    password: Option<&str>,
    oracle: &mut Option<Oracle>,
    what: &str,
) {
    let dir = scratch(&format!("threads-{}", support::fnv64(what.as_bytes())));
    let path = dir.join("a.7z");
    std::fs::write(&path, archive).unwrap();
    if password.is_none()
        && let Some(oracle) = oracle
    {
        let answer = oracle.ask(&path);
        let mut words = answer.split(' ');
        assert_eq!(words.next(), Some("0"), "{what}: {answer:.300}");
        for word in words {
            let mut fields = word.split(':');
            if matches!(fields.next(), Some("d" | "x")) {
                assert_eq!(fields.nth(1), Some("0"), "{what}: {answer:.300}");
            }
        }
    }
    let Some(tool) = seven_zip() else {
        return;
    };
    let run = |args: &[&str], cwd: &Path| {
        let out = Command::new(&tool)
            .args(args)
            .arg(format!("-p{}", password.unwrap_or("-")))
            .arg(&path)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .expect("7zz starts");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "{what}: 7zz {args:?}:\n{text}");
        text
    };
    for mt in ["-mmt=1", "-mmt=4"] {
        let text = run(&["t", "-bd", mt], &dir);
        assert!(text.contains("Everything is Ok"), "{what}: 7zz t:\n{text}");
        assert!(!text.contains("Warnings"), "{what}: 7zz t:\n{text}");
    }
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    run(&["x", "-bd", "-y"], &out);
    for (name, data) in items {
        let at = out.join(name);
        match data {
            None => assert!(at.is_dir(), "{what}: {name}"),
            Some(data) => assert!(std::fs::read(&at).expect(name) == *data, "{what}: {name}"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reads_back_with_any_threads() {
    let mut rng = Rng(0x7ead_5003);
    let mut oracle = Oracle::spawn();
    for (round, (filter, password, solid, blocks)) in [
        (Filter::None, false, true, Lzma2Blocks::Size(1 << 16)),
        (Filter::None, false, true, Lzma2Blocks::Auto),
        (Filter::X86, false, true, Lzma2Blocks::Size(70_000)),
        (Filter::Arm64, false, true, Lzma2Blocks::Size(1 << 18)),
        (Filter::Delta(2), false, true, Lzma2Blocks::Size(1 << 16)),
        (Filter::None, true, true, Lzma2Blocks::Size(1 << 16)),
        (Filter::X86, true, true, Lzma2Blocks::Size(50_000)),
        (Filter::None, false, false, Lzma2Blocks::Size(1 << 16)),
        (Filter::None, true, false, Lzma2Blocks::Size(1 << 17)),
    ]
    .into_iter()
    .enumerate()
    {
        let mut list = items(&mut rng, 60, 200_000);
        list.push(("dir0/large".into(), Some(support::input(&mut rng, 3 << 20))));
        list.push(("dir1/empty".into(), Some(Vec::new())));
        let password = password.then_some("pass wörd 日本");
        let options = WriteOptions {
            filter,
            password: password.map(str::to_string),
            encrypt_headers: password.is_some() && round % 2 == 0,
            key_cycles: 4,
            solid_block_size: if solid { Some(1 << 32) } else { None },
            threads: Threads::Auto,
            ..options(blocks)
        };
        let what = format!("{options:?}");
        let archive = write(&options, &list, round as u64);
        for threads in threads() {
            assert_eq!(
                read_all(&archive, password, threads),
                as_read(&list),
                "{what}: {threads:?}"
            );
        }
        // Each folder whole, and each file with `extract`, from its folder kept.
        let open = Options {
            password: password.map(str::to_string),
            ..Options::default()
        };
        let mut a = Archive::open_with(Cursor::new(&archive), &open).unwrap();
        a.set_threads(Threads::of(4));
        let mut b = Archive::open_with(Cursor::new(&archive), &open).unwrap();
        for folder in 0..a.folders() {
            assert!(a.decode_folder(folder).unwrap() == b.decode_folder(folder).unwrap());
        }
        for (index, (_, data)) in list.iter().enumerate() {
            let got = a.extract(index).unwrap();
            assert!(got == data.clone().unwrap_or_default(), "{what}: {index}");
        }
        check_outside(&archive, &list, password, &mut oracle, &what);
    }
}

#[test]
fn archives_without_blocks_read_the_same() {
    let mut rng = Rng(0x7ead_5004);
    let list = items(&mut rng, 30, 400_000);
    let mut archives = vec![(write(&WriteOptions::default(), &list, 1), None)];
    archives.push((
        write(
            &WriteOptions {
                filter: Filter::X86,
                password: Some("pw".into()),
                key_cycles: 2,
                ..WriteOptions::default()
            },
            &list,
            1,
        ),
        Some("pw"),
    ));
    let committed = support::repository().join("testdata/7z");
    for entry in std::fs::read_dir(&committed).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "7z") {
            archives.push((std::fs::read(&path).unwrap(), Some("password")));
        }
    }
    for (archive, password) in &archives {
        let one = read_all(archive, *password, Threads::One);
        for threads in threads() {
            assert_eq!(read_all(archive, *password, threads), one, "{threads:?}");
        }
    }
    assert_eq!(
        read_all(&archives[0].0, None, Threads::of(8)),
        as_read(&list)
    );
}

/// What 7-Zip writes in threads, its LZMA2 in blocks of 4 times the
/// dictionary, read in threads.
#[test]
fn seven_zip_in_threads() {
    let Some(tool) = seven_zip() else {
        return;
    };
    let dir = scratch("threads-7zz");
    let mut rng = Rng(0x7ead_5005);
    support::write_files(&mut rng, &dir, 60, 400_000);
    for options in [
        "-m0=LZMA2:d=256k -mmt=4",
        "-m0=LZMA2:d=256k:c=300k -mmt=3",
        "-mf=BCJ -m0=LZMA2:d=1m -mmt=8",
        "-m0=LZMA2:d=256k -mmt=4 -pPASSWORD -mhe=on",
    ] {
        let archive = support::make_archive(&tool, &dir, "files", options);
        let password = options.contains("-p").then_some("PASSWORD");
        let one = read_all(&archive, password, Threads::One);
        assert!(
            one.iter().all(|r| matches!(r, Read_::Entry(_, Ok(_)))),
            "{options}"
        );
        for threads in threads() {
            assert_eq!(
                read_all(&archive, password, threads),
                one,
                "{options}: {threads:?}"
            );
        }
        if password.is_none() {
            // It has blocks: the dictionary is reset on the way.
            let a = Archive::open(Cursor::new(&archive)).unwrap();
            let packed = &archive[32..32 + a.folder_packed_size(0) as usize];
            let found = resets(packed);
            assert!(
                found.len() > 1,
                "{options}: {found:?} of {}",
                a.folder_size(0)
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Data damaged in a block: the same errors on the same files, and the same
/// files read, with threads as without.
#[test]
fn damage_reads_as_with_one_thread() {
    let mut rng = Rng(0x7ead_5006);
    let mut list = items(&mut rng, 40, 120_000);
    list.push(("large".into(), Some(support::input(&mut rng, 2 << 20))));
    for (password, blocks, filter) in [
        (None, Lzma2Blocks::Size(1 << 16), Filter::None),
        (None, Lzma2Blocks::Size(1 << 12), Filter::X86),
        (Some("pw"), Lzma2Blocks::Size(1 << 16), Filter::None),
    ] {
        let archive = write(
            &WriteOptions {
                password: password.map(str::to_string),
                key_cycles: 2,
                filter,
                ..options(blocks)
            },
            &list,
            7,
        );
        let packed_end = {
            let a = Archive::open_with(
                Cursor::new(&archive),
                &Options {
                    password: password.map(str::to_string),
                    ..Options::default()
                },
            )
            .unwrap();
            32 + a.folder_packed_size(0) as usize
        };
        for round in 0..60 {
            let bad = if round % 4 == 3 {
                support::damaged(&mut rng, &archive)
            } else {
                let mut bad = archive.clone();
                for _ in 0..1 + rng.below(2) {
                    let at = 32 + rng.below((packed_end - 32) as u64) as usize;
                    match rng.below(3) {
                        0 => bad[at] ^= 1 << rng.below(8),
                        1 => bad[at] = rng.pick(&[0x00, 0x01, 0x02, 0x03, 0x80, 0xE0, 0xFF]),
                        _ => bad[at] = rng.next() as u8,
                    }
                }
                bad
            };
            let one = read_all(&bad, password, Threads::One);
            for threads in [Threads::of(2), Threads::of(8)] {
                let what = format!("{blocks:?} {filter:?} {password:?} round {round}: {threads:?}");
                let got = read_all(&bad, password, threads);
                if filter == Filter::None {
                    same(&got, &one, &what);
                } else {
                    filtered_damage(&got, &one, &list, &what);
                }
            }
        }
    }
}

/// With a filter after LZMA2, the folder's decoder reads ahead of the files,
/// up to 64 KiB, and with one thread an error then fails the file being read
/// when it is met, not the one the damage is in. In threads, each block is
/// decoded whole, and what it gives before the error is read: the error comes
/// at the same file or a later one, and the files between read whole and
/// right. So the same errors, or one file further, and every file read is
/// right.
fn filtered_damage(got: &[Read_], one: &[Read_], items: &[Item], what: &str) {
    let failed = |reads: &[Read_]| {
        reads
            .iter()
            .position(|r| !matches!(r, Read_::Entry(_, Ok(_))))
    };
    let want = as_read(items);
    for reads in [got, one] {
        for read in reads {
            if let Read_::Entry(name, Ok(_)) = read {
                assert!(want.contains(read), "{what}: {name}");
            }
        }
    }
    match (failed(got), failed(one)) {
        (None, None) => {}
        (Some(at), Some(serial)) => {
            assert!(at >= serial, "{what}: {at} before {serial}");
            let error = |r: &Read_| match r {
                Read_::Entry(_, Err(e)) | Read_::Stopped(e) => Some(*e),
                _ => None,
            };
            if at == serial {
                assert_eq!(error(&got[at]), error(&one[serial]), "{what}");
            }
        }
        (got, one) => panic!("{what}: {got:?}, not {one:?}"),
    }
}

/// `extract_7z` with `Options::threads`: the same files, and with
/// `on_damaged` the same entries asked about.
#[test]
fn extraction_in_threads() {
    use hivepack::extract::{OnDamaged, extract_7z, extract_7z_to};
    use std::sync::Mutex;

    let mut rng = Rng(0x7ead_5007);
    let mut list = items(&mut rng, 50, 200_000);
    list.push(("big".into(), Some(support::input(&mut rng, 3 << 20))));
    let archive = write(&options(Lzma2Blocks::Size(1 << 16)), &list, 1);
    let dir = scratch("threads-extract");
    for (i, threads) in threads().into_iter().enumerate() {
        let out = dir.join(format!("out{i}"));
        let mut options = hivepack::extract::Options::default();
        options.threads = threads;
        let mut a = Archive::open(Cursor::new(&archive)).unwrap();
        let summary = extract_7z(&mut a, &out, &options).unwrap();
        let files = list.iter().filter(|(_, d)| d.is_some()).count() as u64;
        assert_eq!(summary.files, files, "{threads:?}");
        for (name, data) in &list {
            match data {
                None => assert!(out.join(name).is_dir()),
                Some(data) => assert!(std::fs::read(out.join(name)).unwrap() == *data),
            }
        }
    }

    // Damaged in the middle of the folder: the same asked about, in a Sink.
    let mut bad = archive.clone();
    let packed = Archive::open(Cursor::new(&archive))
        .unwrap()
        .folder_packed_size(0) as usize;
    for at in [32 + packed / 3, 32 + packed / 2] {
        bad[at] ^= 0x55;
    }
    let asked_with = |threads| {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let kept = asked.clone();
        let mut options = hivepack::extract::Options::default();
        options.threads = threads;
        options.on_damaged = Some(Arc::new(move |e: &hivepack::extract::Error| {
            kept.lock().unwrap().push((e.index, e.kind.to_string()));
            // What was read of it may differ: in threads, all that was
            // decoded before the error.
            OnDamaged::Skip
        }));
        let mut sink = Collect::default();
        let mut a = Archive::open(Cursor::new(&bad)).unwrap();
        let summary = extract_7z_to(&mut a, &mut sink, &options).unwrap();
        let asked = asked.lock().unwrap().clone();
        assert_eq!(summary.damaged.len(), asked.len());
        (asked, sink.files)
    };
    let (asked, files) = asked_with(Threads::One);
    assert!(!asked.is_empty());
    for threads in [Threads::of(2), Threads::Auto] {
        let (asked_mt, files_mt) = asked_with(threads);
        assert_eq!(asked_mt, asked, "{threads:?}");
        // The files read whole are the same.
        let whole = |files: &[(String, Vec<u8>, bool)]| {
            files
                .iter()
                .filter(|f| f.2)
                .map(|f| (f.0.clone(), f.1.clone()))
                .collect::<Vec<_>>()
        };
        assert!(whole(&files_mt) == whole(&files), "{threads:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The files written into it: name, data, and whether they were whole.
#[derive(Default)]
struct Collect {
    files: Vec<(String, Vec<u8>, bool)>,
}

impl hivepack::extract::Sink for Collect {
    fn directory(&mut self, _: &hivepack::extract::Entry<'_>) -> std::io::Result<()> {
        Ok(())
    }
    fn start_file(&mut self, entry: &hivepack::extract::Entry<'_>) -> std::io::Result<()> {
        self.files.push((entry.path.join("/"), Vec::new(), false));
        Ok(())
    }
    fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        if let Some(file) = self.files.last_mut() {
            file.1.extend_from_slice(data);
        }
        Ok(())
    }
    fn finish_file(&mut self) -> std::io::Result<()> {
        if let Some(file) = self.files.last_mut() {
            file.2 = true;
        }
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
