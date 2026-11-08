//! Archives written with threads compressing ahead (`Archive::set_threads`):
//! the same bytes as one thread writes, every way an entry can be written,
//! the same error where one comes, and read back here and by Info-ZIP's
//! `unzip` and `zipinfo` where they are there.

#![allow(clippy::unwrap_used, clippy::field_reassign_with_default)]

use std::io::{self, Cursor, Write};
use std::num::NonZeroU32;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hivepack::Threads;
use hivepack::zip::{
    Archive, ArchiveFlags, BufferSource, Closed, DataSource, ErrorCode, FileAttributes, FileSource,
    Flags, OpenFlags, RandomSource, Stat, cm, em, stat,
};

/// The thread counts compared with one.
fn many() -> [Threads; 3] {
    [
        Threads::Exactly(NonZeroU32::new(2).unwrap()),
        Threads::Exactly(NonZeroU32::new(8).unwrap()),
        Threads::Auto,
    ]
}

/// Words that compress as text does.
fn text(seed: u64, n: usize) -> Vec<u8> {
    const WORDS: [&str; 16] = [
        "the",
        "archive",
        "of",
        "entries",
        "compressed",
        "ahead",
        "in",
        "threads",
        "written",
        "order",
        "zip",
        "data",
        "and",
        "a",
        "byte",
        "for",
    ];
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(WORDS[(x % 16) as usize].as_bytes());
        out.push(if x.is_multiple_of(11) { b'\n' } else { b' ' });
    }
    out.truncate(n);
    out
}

/// Bytes that do not compress.
fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Random bytes that are the same each time an archive is written.
fn counting() -> RandomSource {
    let next = Arc::new(AtomicU64::new(1));
    Arc::new(move |buf: &mut [u8]| {
        for b in buf {
            *b = next.fetch_add(1, Ordering::Relaxed) as u8;
        }
        Ok(())
    })
}

/// The size of each draw of a random source, in order.
#[derive(Clone, Default)]
struct Draws(Arc<Mutex<Vec<usize>>>);

impl Draws {
    fn get(&self) -> Vec<usize> {
        self.0.lock().unwrap().clone()
    }
}

/// Random bytes as [`counting`] gives them, each draw kept in `draws`; the
/// draw numbered `fail_at` (from 0) fails, and those after it. Each must be
/// drawn on the thread writing, not one of those compressing.
fn recording(draws: &Draws, fail_at: Option<usize>) -> RandomSource {
    let draws = draws.clone();
    let next = Arc::new(AtomicU64::new(1));
    Arc::new(move |buf: &mut [u8]| {
        assert_ne!(
            std::thread::current().name(),
            Some("zip-compress"),
            "drawn in a thread compressing"
        );
        let mut draws = draws.0.lock().unwrap();
        let n = draws.len();
        draws.push(buf.len());
        if fail_at.is_some_and(|at| n >= at) {
            return Err(io::Error::other("no more"));
        }
        for b in buf {
            *b = next.fetch_add(1, Ordering::Relaxed) as u8;
        }
        Ok(())
    })
}

/// Not `Seek`: what is written goes where it goes.
struct Pipe(Vec<u8>);

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A source over bytes that fails once `fail_at` bytes are read, or that
/// does not tell its size.
struct Odd {
    data: Arc<[u8]>,
    fail_at: Option<u64>,
    sized: bool,
    reads: Arc<AtomicUsize>,
}

impl Odd {
    fn failing(data: Vec<u8>, at: u64) -> Odd {
        Odd {
            data: data.into(),
            fail_at: Some(at),
            sized: true,
            reads: Arc::default(),
        }
    }

    fn without_size(data: Vec<u8>) -> Odd {
        Odd {
            data: data.into(),
            fail_at: None,
            sized: false,
            reads: Arc::default(),
        }
    }
}

impl DataSource for Odd {
    fn stat(&self) -> hivepack::zip::Result<Stat<'static>> {
        let mut st = Stat::default();
        st.valid = stat::MTIME;
        st.mtime = 1_700_000_000;
        if self.sized {
            st.valid |= stat::SIZE;
            st.size = self.data.len() as u64;
        }
        Ok(st)
    }
    fn file_attributes(&self) -> hivepack::zip::Result<FileAttributes> {
        Ok(FileAttributes::default())
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> hivepack::zip::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if let Some(at) = self.fail_at
            && offset + buf.len() as u64 > at
        {
            if offset < at {
                // What comes before the failure, first.
                let n = (at - offset) as usize;
                buf[..n].copy_from_slice(&self.data[offset as usize..at as usize]);
                return Ok(n);
            }
            return Err(hivepack::zip::Error::new(ErrorCode::Read, 5));
        }
        let rest = self.data.get(offset as usize..).unwrap_or(&[]);
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(n)
    }
}

/// An entry to add: its data, how it is compressed and encrypted.
#[derive(Clone)]
struct Spec {
    name: String,
    data: Arc<[u8]>,
    /// the method and level; none leaves libzip's default
    method: Option<(i32, u32)>,
    encryption: Option<u16>,
    /// the entry's own password, or the archive's default
    password: Password,
    /// the time set for the entry, which ZipCrypto's header then ends with
    mtime: Option<i64>,
    source: SourceKind,
}

#[derive(Clone, Copy, PartialEq)]
enum Password {
    Own(&'static [u8]),
    Default,
}

impl Spec {
    fn password(&self) -> &'static [u8] {
        match self.password {
            Password::Own(password) => password,
            Password::Default => DEFAULT_PASSWORD,
        }
    }

    fn encrypted(mut self, method: u16) -> Spec {
        self.encryption = Some(method);
        self
    }
}

#[derive(Clone, Copy, PartialEq)]
enum SourceKind {
    Buffer,
    Unsized,
    FailingAt(u64),
}

fn spec(name: impl Into<String>, data: Vec<u8>, method: Option<(i32, u32)>) -> Spec {
    Spec {
        name: name.into(),
        data: data.into(),
        method,
        encryption: None,
        password: Password::Own(PASSWORD),
        mtime: None,
        source: SourceKind::Buffer,
    }
}

const PASSWORD: &[u8] = b"secret";
const DEFAULT_PASSWORD: &[u8] = b"the default";

fn deflate(level: u32) -> Option<(i32, u32)> {
    Some((i32::from(cm::DEFLATE), level))
}

/// The archive of `specs`, from nothing, to be written with `threads`.
fn archive(specs: &[Spec], threads: Threads) -> Archive<&'static [u8]> {
    archive_drawing(specs, threads, counting())
}

/// The archive of `specs`, its random bytes from `random`.
fn archive_drawing(
    specs: &[Spec],
    threads: Threads,
    random: RandomSource,
) -> Archive<&'static [u8]> {
    let mut archive = Archive::open(&[][..], OpenFlags(0)).unwrap();
    archive.set_random_source(Some(random));
    archive.set_default_password(Some(DEFAULT_PASSWORD));
    archive.set_threads(threads);
    add(&mut archive, specs);
    archive
}

fn add<R: hivepack::zip::ReadAt>(archive: &mut Archive<R>, specs: &[Spec]) {
    for s in specs {
        let index = match s.source {
            SourceKind::Buffer => archive.file_add(
                s.name.as_bytes(),
                BufferSource::with_mtime(s.data.clone(), 1_700_000_000),
                Flags::NONE,
            ),
            SourceKind::Unsized => archive.file_add(
                s.name.as_bytes(),
                Odd::without_size(s.data.to_vec()),
                Flags::NONE,
            ),
            SourceKind::FailingAt(at) => archive.file_add(
                s.name.as_bytes(),
                Odd::failing(s.data.to_vec(), at),
                Flags::NONE,
            ),
        }
        .unwrap();
        if let Some((method, level)) = s.method {
            archive.set_file_compression(index, method, level).unwrap();
        }
        if let Some(method) = s.encryption {
            let password = match s.password {
                Password::Own(password) => Some(password),
                Password::Default => None,
            };
            archive
                .file_set_encryption(index, method, password)
                .unwrap();
        }
        if let Some(mtime) = s.mtime {
            archive.file_set_mtime(index, mtime, Flags::NONE).unwrap();
        }
    }
}

/// What writing gives: the bytes written, and the error if there was one.
type Written = (Vec<u8>, Result<Closed, hivepack::zip::Error>);

fn seekable<R: hivepack::zip::ReadAt>(archive: &mut Archive<R>) -> Written {
    let mut out = Cursor::new(Vec::new());
    let closed = archive.close_to(&mut out);
    (out.into_inner(), closed)
}

fn streamed<R: hivepack::zip::ReadAt>(archive: &mut Archive<R>) -> Written {
    let mut out = Pipe(Vec::new());
    let closed = archive.close_to_stream(&mut out);
    (out.0, closed)
}

/// `specs` written with each thread count, to a file and to a stream, must
/// give what one thread gives; that is returned, for a file then a stream.
fn same_bytes(what: &str, specs: &[Spec]) -> (Written, Written) {
    let one_seek = seekable(&mut archive(specs, Threads::One));
    let one_stream = streamed(&mut archive(specs, Threads::One));
    for threads in many() {
        let seek = seekable(&mut archive(specs, threads));
        assert!(seek.1 == one_seek.1, "{what}, {threads:?}: {:?}", seek.1);
        assert!(seek.0 == one_seek.0, "{what}, {threads:?}: bytes differ");
        let stream = streamed(&mut archive(specs, threads));
        assert!(stream.1 == one_stream.1, "{what}, {threads:?}, stream");
        assert!(
            stream.0 == one_stream.0,
            "{what}, {threads:?}, stream: bytes differ"
        );
    }
    (one_seek, one_stream)
}

/// Each entry read back with every check, against what was added.
fn reads_back(bytes: &[u8], specs: &[Spec]) {
    let mut archive = Archive::open(bytes, OpenFlags::CHECKCONS | OpenFlags::RDONLY).unwrap();
    archive.set_default_password(Some(PASSWORD));
    assert_eq!(archive.get_num_entries(Flags::NONE), specs.len() as u64);
    for (i, s) in specs.iter().enumerate() {
        assert_eq!(
            archive.get_name(i as u64, Flags::NONE).unwrap(),
            s.name.as_bytes()
        );
        let mut body = Vec::new();
        let password = s.encryption.map(|_| s.password());
        io::copy(
            &mut archive
                .fopen_index_encrypted(i as u64, Flags::NONE, password)
                .unwrap(),
            &mut body,
        )
        .unwrap();
        assert!(body == *s.data, "{}", s.name);
    }
}

/// `unzip -t` and `zipinfo` find `bytes` sound, where they are there: what
/// `unzip` reads, at least.
fn info_zip_agrees(bytes: &[u8], test: &str, password: bool) {
    let dir = std::env::temp_dir().join(format!("hivepack-threads-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let zip = dir.join("a.zip");
    std::fs::write(&zip, bytes).unwrap();
    let run = |tool: &str, args: &[&str]| {
        let out = Command::new(tool)
            .args(args)
            .arg(&zip)
            .stdin(Stdio::null())
            .output();
        if let Ok(o) = out {
            let said = String::from_utf8_lossy(&o.stdout).into_owned()
                + &String::from_utf8_lossy(&o.stderr);
            // `unzip` skips what it cannot read (bzip2, LZMA, XZ, Zstandard
            // and WinZip AES, as Debian builds it), with status 81.
            let skipped = o.status.code() == Some(81) && said.contains("No errors detected");
            assert!(o.status.success() || skipped, "{tool}: {said}");
        }
    };
    if password {
        run("unzip", &["-tq", "-P", "secret"]);
    } else {
        run("unzip", &["-tq"]);
    }
    run("zipinfo", &["-v"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn many_small_files() {
    let specs: Vec<Spec> = (0..600)
        .map(|i| {
            let n = (i * 37) % 3000;
            let method = match i % 4 {
                0 => None,
                1 => deflate(1),
                2 => deflate(9),
                _ => Some((i32::from(cm::STORE), 0)),
            };
            spec(format!("dir/file{i}.txt"), text(i as u64, n), method)
        })
        .collect();
    let (seek, stream) = same_bytes("small files", &specs);
    reads_back(&seek.0, &specs);
    reads_back(&stream.0, &specs);
    info_zip_agrees(&seek.0, "small", false);
    info_zip_agrees(&stream.0, "small-stream", false);
}

#[test]
fn empty_files_and_one_byte() {
    let mut specs = Vec::new();
    for i in 0..40u64 {
        let method = match i % 4 {
            0 => None,
            1 => deflate(6),
            2 => Some((i32::from(cm::BZIP2), 9)),
            _ => Some((i32::from(cm::ZSTD), 3)),
        };
        let data = if i % 2 == 0 { Vec::new() } else { vec![b'x'] };
        specs.push(spec(format!("e{i}"), data, method));
    }
    let (seek, stream) = same_bytes("empty", &specs);
    reads_back(&seek.0, &specs);
    reads_back(&stream.0, &specs);
}

#[test]
fn every_method() {
    let mut specs = Vec::new();
    let methods = [
        (i32::from(cm::DEFLATE), 0),
        (i32::from(cm::DEFLATE), 3),
        (cm::DEFAULT, 0),
        (i32::from(cm::BZIP2), 1),
        (i32::from(cm::BZIP2), 9),
        (i32::from(cm::LZMA), 2),
        (i32::from(cm::XZ), 1),
        (i32::from(cm::ZSTD), 1),
        (i32::from(cm::ZSTD), 19),
    ];
    for (i, &method) in methods.iter().enumerate() {
        for (j, n) in [0usize, 100, 8191, 8192, 70_000, 300_000]
            .into_iter()
            .enumerate()
        {
            let data = if j % 2 == 0 {
                text((i * 10 + j) as u64, n)
            } else {
                noise((i * 10 + j) as u64, n)
            };
            specs.push(spec(format!("m{i}/{j}"), data, Some(method)));
        }
    }
    let (seek, stream) = same_bytes("methods", &specs);
    reads_back(&seek.0, &specs);
    reads_back(&stream.0, &specs);
    info_zip_agrees(&seek.0, "methods", false);
}

/// Encrypted on the thread writing, in order: the random bytes are drawn as
/// with one thread. `ZIP_CM_DEFAULT` stores what does not compress in the
/// first read, which the header of the encryption makes smaller: data of
/// about that size, compressing and not.
#[test]
fn encrypted() {
    let mut specs = Vec::new();
    let mut i = 0u64;
    for encryption in [em::AES_128, em::AES_192, em::AES_256, em::TRAD_PKWARE] {
        for method in [None, deflate(9), Some((i32::from(cm::ZSTD), 3))] {
            for n in [0usize, 5, 8170, 8174, 8178, 8180, 8182, 8192, 8193, 40_000] {
                i += 1;
                let data = if i.is_multiple_of(3) {
                    text(i, n)
                } else {
                    noise(i, n)
                };
                let mut s = spec(format!("x{i}"), data, method);
                s.encryption = Some(encryption);
                specs.push(s);
            }
        }
    }
    // And some not encrypted among them.
    for n in [8180usize, 8192, 8193] {
        specs.push(spec(format!("plain{n}"), noise(n as u64, n), None));
    }
    let (seek, stream) = same_bytes("encrypted", &specs);
    reads_back(&seek.0, &specs);
    reads_back(&stream.0, &specs);
    info_zip_agrees(&seek.0, "encrypted", true);
}

/// Sources that do not tell their size, written on the thread writing (and
/// Zip64 for it); stored entries, and a mix around them.
#[test]
fn unsized_and_stored() {
    let mut specs = Vec::new();
    for i in 0..30u64 {
        let mut s = spec(
            format!("u{i}"),
            text(i, (i as usize) * 1000),
            if i % 3 == 0 { None } else { deflate(5) },
        );
        if i % 2 == 0 {
            s.source = SourceKind::Unsized;
        }
        if i % 5 == 0 {
            s.method = Some((i32::from(cm::STORE), 0));
        }
        specs.push(s);
    }
    let (seek, stream) = same_bytes("unsized", &specs);
    reads_back(&seek.0, &specs);
    reads_back(&stream.0, &specs);
}

/// A source that fails partway: the same error, at the same entry, and the
/// same bytes written before it, with the entries after it compressed ahead.
#[test]
fn a_source_that_fails() {
    for (what, at, encryption) in [
        ("first read", 0, None),
        ("later read", 50_000, None),
        ("later read, AES", 50_000, Some(em::AES_256)),
        ("first read, ZipCrypto", 10, Some(em::TRAD_PKWARE)),
    ] {
        let mut specs: Vec<Spec> = (0..20u64)
            .map(|i| spec(format!("f{i}"), text(i, 100_000), None))
            .collect();
        specs[7].source = SourceKind::FailingAt(at);
        specs[7].encryption = encryption;
        // A later one fails too: the first is the one told.
        specs[15].source = SourceKind::FailingAt(0);
        let (seek, stream) = same_bytes(what, &specs);
        for (how, written) in [("seek", seek), ("stream", stream)] {
            // With encryption, a short read ends the data: what fails then
            // is what the sizes say.
            let err = written.1.expect_err(how);
            if encryption.is_none() {
                assert_eq!(err.code(), ErrorCode::Read, "{what}, {how}");
            }
        }
    }
}

/// The threads compress the entries after one too large for them while the
/// thread writing compresses it. Two threads have 64 MiB.
#[test]
fn larger_than_the_threads_hold() {
    let mut specs = vec![spec("big", text(1, 70 << 20), deflate(1))];
    for i in 0..50u64 {
        specs.push(spec(format!("after{i}"), text(i + 2, 200_000), deflate(1)));
    }
    specs.push(spec("big2", text(99, 40 << 20), deflate(1)));
    specs.push(spec("big3", text(98, 40 << 20), deflate(1)));
    let one = seekable(&mut archive(&specs, Threads::One));
    let two = seekable(&mut archive(
        &specs,
        Threads::Exactly(NonZeroU32::new(2).unwrap()),
    ));
    assert!(one.1 == two.1);
    assert!(one.0 == two.0, "bytes differ");
    let stream_one = streamed(&mut archive(&specs, Threads::One));
    let stream_all = streamed(&mut archive(&specs, Threads::Auto));
    assert!(stream_one.0 == stream_all.0, "stream: bytes differ");
    reads_back(&one.0, &specs);
}

/// More than 65,535 entries: the Zip64 end of central directory.
#[test]
fn zip64_count() {
    let specs: Vec<Spec> = (0..65_600u64)
        .map(|i| {
            let data = if i % 1000 == 0 {
                text(i, 3000)
            } else {
                vec![(i % 251) as u8]
            };
            spec(
                format!("{i}"),
                data,
                if i % 2 == 0 { deflate(1) } else { None },
            )
        })
        .collect();
    let one = seekable(&mut archive(&specs, Threads::One));
    let all = seekable(&mut archive(&specs, Threads::Auto));
    assert!(one.0 == all.0, "bytes differ");
    let stream_one = streamed(&mut archive(&specs, Threads::One));
    let stream_all = streamed(&mut archive(&specs, Threads::Auto));
    assert!(stream_one.0 == stream_all.0, "stream: bytes differ");
    reads_back(&one.0, &specs);
}

/// An archive opened and edited: entries kept as they are, renamed,
/// compressed again from the archive, deleted, replaced and added, the new
/// data compressed ahead.
#[test]
fn edited_archive() {
    let first: Vec<Spec> = (0..40u64)
        .map(|i| {
            spec(
                format!("old{i}"),
                text(i, 5000 + i as usize * 300),
                deflate(6),
            )
        })
        .collect();
    let (base, _) = same_bytes("base", &first);
    let base: &'static [u8] = Vec::leak(base.0);
    let edit = |threads: Threads| {
        let mut archive = Archive::open(base, OpenFlags::CHECKCONS).unwrap();
        archive.set_random_source(Some(counting()));
        archive.set_threads(threads);
        archive.file_rename(1, b"renamed", Flags::NONE).unwrap();
        archive.delete(2).unwrap();
        archive
            .set_file_compression(3, i32::from(cm::BZIP2), 5)
            .unwrap();
        archive
            .file_set_encryption(4, em::AES_256, Some(PASSWORD))
            .unwrap();
        archive
            .file_replace(
                5,
                BufferSource::with_mtime(text(500, 20_000), 1_700_000_000),
                Flags::NONE,
            )
            .unwrap();
        archive
            .set_file_compression(5, i32::from(cm::XZ), 1)
            .unwrap();
        let more: Vec<Spec> = (0..30u64)
            .map(|i| spec(format!("new{i}"), text(600 + i, 9000), deflate(9)))
            .collect();
        add(&mut archive, &more);
        let cloned = {
            let mut out = Cursor::new(Vec::new());
            let closed = archive.close_to_cloning(&mut out, |_| true);
            (out.into_inner(), closed)
        };
        (seekable(&mut archive), streamed(&mut archive), cloned)
    };
    let one = edit(Threads::One);
    for threads in many() {
        let got = edit(threads);
        assert!(got.0.0 == one.0.0, "{threads:?}: bytes differ");
        assert!(got.1.0 == one.1.0, "{threads:?}, stream: bytes differ");
        assert!(got.2.0 == one.2.0, "{threads:?}, cloned: bytes differ");
    }
    info_zip_agrees(&one.0.0, "edited", true);
}

/// Torrentzip's form: the entries sorted, deflated at level 9.
#[test]
fn torrentzip() {
    let specs: Vec<Spec> = (0..50u64)
        .map(|i| spec(format!("t{}", 50 - i), text(i, 4000), None))
        .collect();
    let write = |threads: Threads| {
        let mut a = archive(&specs, threads);
        a.set_archive_flag(ArchiveFlags::WANT_TORRENTZIP, true)
            .unwrap();
        seekable(&mut a)
    };
    let one = write(Threads::One);
    for threads in many() {
        assert!(write(threads).0 == one.0, "{threads:?}: bytes differ");
    }
}

/// A file on disk, as packwing adds them.
#[test]
fn files_on_disk() {
    let dir = std::env::temp_dir().join(format!("hivepack-threads-files-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut paths = Vec::new();
    for i in 0..60u64 {
        let path = dir.join(format!("{i}.txt"));
        std::fs::write(&path, text(i, 1000 + (i as usize) * 4000)).unwrap();
        paths.push(path);
    }
    let write = |threads: Threads| {
        let mut archive = Archive::open(&[][..], OpenFlags(0)).unwrap();
        archive.set_random_source(Some(counting()));
        archive.set_threads(threads);
        for (i, path) in paths.iter().enumerate() {
            let index = archive
                .file_add(
                    format!("{i}.txt").as_bytes(),
                    FileSource::new(path, 0, None).unwrap(),
                    Flags::NONE,
                )
                .unwrap();
            archive
                .set_file_compression(index, i32::from(cm::DEFLATE), 6)
                .unwrap();
            if i % 3 == 0 {
                archive
                    .file_set_encryption(index, em::AES_256, Some(PASSWORD))
                    .unwrap();
            }
        }
        (seekable(&mut archive).0, streamed(&mut archive).0)
    };
    let one = write(Threads::One);
    for threads in many() {
        assert!(write(threads) == one, "{threads:?}: bytes differ");
    }
    info_zip_agrees(&one.0, "disk", true);
    info_zip_agrees(&one.1, "disk-stream", true);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `specs` written as [`same_bytes`] writes them, drawing from a source
/// that keeps each draw (`fail_at` failing): the same draws, in the same
/// order and sizes, as with one thread, as well as the same bytes. That of
/// one thread is returned, for a file then a stream.
fn same_draws(what: &str, specs: &[Spec], fail_at: Option<usize>) -> (Written, Written) {
    let write = |threads: Threads, stream: bool| {
        let draws = Draws::default();
        let mut archive = archive_drawing(specs, threads, recording(&draws, fail_at));
        let written = match stream {
            true => streamed(&mut archive),
            false => seekable(&mut archive),
        };
        (written, draws.get())
    };
    let mut ones = Vec::new();
    for stream in [false, true] {
        let (one, one_draws) = write(Threads::One, stream);
        for threads in many() {
            let (got, draws) = write(threads, stream);
            assert!(got.1 == one.1, "{what}, {threads:?}, {stream}: {:?}", got.1);
            assert!(
                got.0 == one.0,
                "{what}, {threads:?}, {stream}: bytes differ"
            );
            assert_eq!(draws, one_draws, "{what}, {threads:?}, {stream}: draws");
        }
        ones.push(one);
    }
    let stream = ones.pop().unwrap();
    (ones.pop().unwrap(), stream)
}

/// Many small files, encrypted in threads with each method, among others
/// not encrypted: the same bytes and draws as with one thread, and `unzip`
/// reads what it can of them.
#[test]
fn encrypted_in_threads() {
    let methods = [
        Some(em::AES_128),
        Some(em::AES_192),
        Some(em::AES_256),
        Some(em::TRAD_PKWARE),
        None,
    ];
    let specs: Vec<Spec> = (0..500u64)
        .map(|i| {
            let n = ((i * 53) % 9000) as usize;
            let data = if i % 7 == 0 { noise(i, n) } else { text(i, n) };
            let method = match i % 3 {
                0 => None,
                1 => deflate(6),
                _ => Some((i32::from(cm::ZSTD), 3)),
            };
            let mut s = spec(format!("enc/{i}"), data, method);
            s.encryption = methods[(i % 5) as usize];
            s
        })
        .collect();
    let (seek, stream) = same_draws("encrypted in threads", &specs, None);
    reads_back(&seek.0, &specs);
    reads_back(&stream.0, &specs);
    info_zip_agrees(&seek.0, "enc-threads", true);
    info_zip_agrees(&stream.0, "enc-threads-stream", true);
}

/// A password up to its first NUL byte, as libzip takes it.
fn c_str(password: &'static [u8]) -> &'static [u8] {
    let end = password
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(password.len());
    &password[..end]
}

/// Each entry with its own password, or the archive's default; ZipCrypto
/// whose header ends with the time set for the entry, or with the source's.
#[test]
fn passwords_and_times() {
    const OWN: [&[u8]; 3] = [b"one", b"two\0after the end", PASSWORD];
    let specs: Vec<Spec> = (0..240u64)
        .map(|i| {
            let mut s = spec(format!("p{i}"), text(i, 100 + i as usize * 37), deflate(9));
            s.encryption = Some(if i % 2 == 0 {
                em::TRAD_PKWARE
            } else {
                em::AES_256
            });
            s.password = match i % 4 {
                0 | 1 => Password::Default,
                _ => Password::Own(OWN[(i / 4 % 3) as usize]),
            };
            if i % 3 == 0 {
                s.mtime = Some(1_600_000_000 + i as i64 * 1000);
            }
            s
        })
        .collect();
    let (seek, stream) = same_draws("passwords", &specs, None);
    let specs: Vec<Spec> = specs
        .iter()
        .map(|s| {
            let mut s = s.clone();
            s.password = Password::Own(c_str(s.password()));
            s
        })
        .collect();
    reads_back(&seek.0, &specs);
    reads_back(&stream.0, &specs);
}

/// Encrypted entries the threads do not encrypt, among those they do: too
/// large for what the threads hold (the bytes of those after them are drawn
/// before they are written), stored, not telling their size; and some of
/// the default method that are stored as they do not compress.
#[test]
fn encrypted_on_the_thread_writing() {
    let methods = [em::AES_256, em::TRAD_PKWARE, em::AES_128];
    let mut specs = Vec::new();
    let mut i = 0u64;
    let mut next = |data: Vec<u8>, method: Option<(i32, u32)>| {
        i += 1;
        spec(format!("w{i}"), data, method).encrypted(methods[(i % 3) as usize])
    };
    for round in 0..2u64 {
        for j in 0..20 {
            specs.push(next(text(round * 100 + j, 3000), deflate(6)));
        }
        // Two threads hold 64 MiB: this is written on the thread writing.
        specs.push(next(text(round, 66 << 20), deflate(1)));
        for j in 0..10 {
            specs.push(next(noise(round * 10 + j, 9000), None));
            specs.push(next(
                text(round * 10 + j, 5000),
                Some((i32::from(cm::STORE), 0)),
            ));
            let mut no_size = next(text(round * 10 + j, 4000), deflate(6));
            no_size.source = SourceKind::Unsized;
            specs.push(no_size);
            specs.push(spec(format!("plain{round}-{j}"), text(j, 2000), deflate(6)));
        }
    }
    let two = Threads::Exactly(NonZeroU32::new(2).unwrap());
    for stream in [false, true] {
        let write = |threads: Threads| {
            let draws = Draws::default();
            let mut archive = archive_drawing(&specs, threads, recording(&draws, None));
            let written = match stream {
                true => streamed(&mut archive),
                false => seekable(&mut archive),
            };
            (written, draws.get())
        };
        let one = write(Threads::One);
        assert!(one.0.1.is_ok());
        for threads in [two, Threads::Auto] {
            let got = write(threads);
            assert!(got.0.1 == one.0.1, "{threads:?}, {stream}");
            assert!(got.0.0 == one.0.0, "{threads:?}, {stream}: bytes differ");
            assert_eq!(got.1, one.1, "{threads:?}, {stream}: draws");
        }
        reads_back(&one.0.0, &specs);
    }
}

/// An archive opened and edited, entries of it encrypted again or
/// compressed again among new ones encrypted in threads: what those draw is
/// told only when they are written, so none is drawn past them before.
#[test]
fn encrypted_again_from_the_archive() {
    let first: Vec<Spec> = (0..40u64)
        .map(|i| {
            let s = spec(
                format!("old{i}"),
                text(i, 3000 + i as usize * 100),
                deflate(6),
            );
            if i % 3 == 0 {
                s.encrypted(em::TRAD_PKWARE)
            } else {
                s
            }
        })
        .collect();
    let (base, _) = same_bytes("base", &first);
    let base: &'static [u8] = Vec::leak(base.0);
    let edit = |threads: Threads, stream: bool| {
        let draws = Draws::default();
        let mut archive = Archive::open(base, OpenFlags::CHECKCONS).unwrap();
        archive.set_random_source(Some(recording(&draws, None)));
        archive.set_default_password(Some(PASSWORD));
        archive.set_threads(threads);
        for i in 0..40u64 {
            match i % 5 {
                0 => archive.file_set_encryption(i, em::AES_192, Some(b"new")),
                1 => archive.set_file_compression(i, i32::from(cm::BZIP2), 3),
                2 => archive.file_set_encryption(i, em::NONE, None),
                _ => Ok(()),
            }
            .unwrap();
        }
        let more: Vec<Spec> = (0..60u64)
            .map(|i| {
                spec(format!("new{i}"), text(600 + i, 7000), deflate(9)).encrypted(if i % 2 == 0 {
                    em::AES_256
                } else {
                    em::TRAD_PKWARE
                })
            })
            .collect();
        add(&mut archive, &more);
        // New ones replacing old ones, among them.
        for i in (3..40u64).step_by(6) {
            archive
                .file_replace(
                    i,
                    BufferSource::with_mtime(text(900 + i, 6000), 1_700_000_000),
                    Flags::NONE,
                )
                .unwrap();
            archive
                .file_set_encryption(i, em::AES_128, Some(b"replaced"))
                .unwrap();
        }
        let written = match stream {
            true => streamed(&mut archive),
            false => seekable(&mut archive),
        };
        (written, draws.get())
    };
    for stream in [false, true] {
        let one = edit(Threads::One, stream);
        assert!(one.0.1.is_ok(), "{:?}", one.0.1);
        assert!(!one.1.is_empty());
        for threads in many() {
            let got = edit(threads, stream);
            assert!(got.0.1 == one.0.1, "{threads:?}, {stream}");
            assert!(got.0.0 == one.0.0, "{threads:?}, {stream}: bytes differ");
            assert_eq!(got.1, one.1, "{threads:?}, {stream}: draws");
        }
    }
}

/// The random source failing at a draw: the same error, after the same
/// bytes, and no draw after it.
#[test]
fn random_source_fails() {
    let specs: Vec<Spec> = (0..120u64)
        .map(|i| {
            let s = spec(format!("r{i}"), text(i, 2000 + i as usize * 50), deflate(6));
            match i % 3 {
                0 => s.encrypted(em::AES_256),
                1 => s.encrypted(em::TRAD_PKWARE),
                _ => s,
            }
        })
        .collect();
    for at in [0, 1, 17, 60] {
        let (seek, stream) = same_draws(&format!("fails at {at}"), &specs, Some(at));
        for written in [seek, stream] {
            let err = written.1.unwrap_err();
            assert_eq!(err.code(), ErrorCode::Internal, "{at}");
        }
    }
}

/// An entry that fails, encrypted: the same error and bytes as one thread.
/// What one thread draws is drawn first, in order; only the entries after
/// the one that failed may have drawn more.
#[test]
fn encrypted_entry_fails() {
    let mut specs: Vec<Spec> = (0..60u64)
        .map(|i| spec(format!("e{i}"), text(i, 30_000), deflate(6)).encrypted(em::AES_256))
        .collect();
    specs[20].source = SourceKind::FailingAt(10_000);
    // WinZip AES refuses an empty password, once it drew the salt.
    specs[40].password = Password::Own(b"");
    for (what, specs) in [
        ("source", specs.clone()),
        ("password", specs[21..].to_vec()),
    ] {
        for stream in [false, true] {
            let write = |threads: Threads| {
                let draws = Draws::default();
                let mut archive = archive_drawing(&specs, threads, recording(&draws, None));
                let written = match stream {
                    true => streamed(&mut archive),
                    false => seekable(&mut archive),
                };
                (written, draws.get())
            };
            let one = write(Threads::One);
            assert!(one.0.1.is_err(), "{what}");
            for threads in many() {
                let got = write(threads);
                assert!(got.0.1 == one.0.1, "{what}, {threads:?}, {stream}");
                assert!(
                    got.0.0 == one.0.0,
                    "{what}, {threads:?}, {stream}: bytes differ"
                );
                assert!(
                    got.1.starts_with(&one.1),
                    "{what}, {threads:?}, {stream}: draws"
                );
            }
        }
    }
}

/// What `DeflateMt` makes of `data` at `level`, raw: the stream an entry
/// deflated in blocks holds.
fn in_blocks(data: &[u8], level: u32) -> Vec<u8> {
    use hivepack::deflate::{DeflateMt, Flush, InBuffer, MtOptions, OutBuffer, Status};
    let mut blocks = DeflateMt::new(&MtOptions {
        level: level as i32,
        raw: true,
        ..MtOptions::default()
    })
    .unwrap();
    let mut out = vec![0; data.len() + data.len() / 100 + (64 << 10)];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(data);
    let status = blocks
        .deflate(&mut output, &mut input, Flush::Finish)
        .unwrap();
    assert_eq!(status, Status::StreamEnd);
    let n = output.pos;
    out.truncate(n);
    out
}

/// Entry `i`'s data as it is in `bytes`, compressed.
fn compressed(bytes: &[u8], i: u64) -> Vec<u8> {
    let archive = Archive::open(bytes, OpenFlags::RDONLY).unwrap();
    let mut data = Vec::new();
    io::copy(
        &mut archive.fopen_index(i, Flags::COMPRESSED).unwrap(),
        &mut data,
    )
    .unwrap();
    data
}

/// Deflate in blocks, asked: each entry deflated, small ones in the threads
/// ahead and one past 32 MiB where it is written, is the stream `DeflateMt`
/// makes, the archive the same whatever the threads, to a file or a stream,
/// encrypted too, and read back by the port and by Info-ZIP. Torrentzip is
/// zlib's still.
#[test]
fn deflate_in_blocks() {
    let mut specs: Vec<Spec> = (0..12u64)
        .map(|i| {
            spec(
                format!("small{i}"),
                text(i, 150_000 + 997 * i as usize),
                deflate(6),
            )
        })
        .collect();
    specs.push(spec("big", text(77, 34 << 20), deflate(1)));
    specs.push(spec("default", text(78, 600_000), None));
    let mut unsized_ = spec("unsized", text(79, 3 << 20), deflate(6));
    unsized_.source = SourceKind::Unsized;
    specs.push(unsized_);
    let mut aes = spec("aes", text(80, 2 << 20), deflate(6));
    aes.encryption = Some(em::AES_256);
    specs.push(aes);
    let write = |threads: Threads, stream: bool| {
        let mut a = archive(&specs, threads);
        a.set_deflate_in_blocks(true);
        if stream {
            streamed(&mut a)
        } else {
            seekable(&mut a)
        }
    };
    let one = write(Threads::One, false);
    let one_stream = write(Threads::One, true);
    assert!(one.1.is_ok() && one_stream.1.is_ok());
    for threads in many() {
        assert!(
            write(threads, false).0 == one.0,
            "{threads:?}: bytes differ"
        );
        assert!(
            write(threads, true).0 == one_stream.0,
            "{threads:?}, stream: bytes differ"
        );
    }
    for (i, s) in specs.iter().enumerate() {
        if s.encryption.is_some() {
            continue;
        }
        let level = s.method.map_or(9, |(_, level)| level);
        assert!(
            compressed(&one.0, i as u64) == in_blocks(&s.data, level),
            "{}",
            s.name
        );
    }
    reads_back(&one.0, &specs);
    reads_back(&one_stream.0, &specs);
    info_zip_agrees(&one.0, "blocks", true);
    // Off, as libzip deflates: one zlib stream, not blocks.
    let off = seekable(&mut archive(&specs, Threads::Auto));
    let big = specs.iter().position(|s| s.name == "big").unwrap() as u64;
    assert!(compressed(&off.0, big) != compressed(&one.0, big));

    let torrent: Vec<Spec> = (0..20u64)
        .map(|i| spec(format!("t{i}"), text(i, 200_000), None))
        .collect();
    let write = |blocks: bool| {
        let mut a = archive(&torrent, Threads::Auto);
        a.set_deflate_in_blocks(blocks);
        a.set_archive_flag(ArchiveFlags::WANT_TORRENTZIP, true)
            .unwrap();
        seekable(&mut a)
    };
    assert!(write(true).0 == write(false).0, "torrentzip in blocks");
}
