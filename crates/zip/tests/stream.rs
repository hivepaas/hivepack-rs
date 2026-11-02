//! Archives written to what only goes forwards, read back here and, where they are
//! there, by `7zz`, Info-ZIP's `unzip` and Python's `zipfile`.

#![allow(clippy::unwrap_used, clippy::field_reassign_with_default)]

use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use hivepack_zip::{
    Archive, BufferSource, Closed, DataSource, ErrorCode, FileAttributes, Flags, OpenFlags, Stat,
    cm, em, stat,
};

/// `7zz`, if `scripts/testdata.py` has fetched it.
fn seven_zip() -> Option<PathBuf> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata"));
    let tool = cache.join("7zz/7zz");
    tool.exists().then_some(tool)
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

/// Bytes that do not compress.
fn noise(n: usize) -> Vec<u8> {
    let mut x = 88172645463325252u64;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// A source that does not say how big it is.
struct NoSize(Arc<[u8]>);

impl DataSource for NoSize {
    fn stat(&self) -> hivepack_zip::Result<Stat<'static>> {
        let mut st = Stat::default();
        st.valid = stat::MTIME;
        st.mtime = 1_700_000_000;
        Ok(st)
    }
    fn file_attributes(&self) -> hivepack_zip::Result<FileAttributes> {
        Ok(FileAttributes::default())
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> hivepack_zip::Result<usize> {
        let rest = self.0.get(offset as usize..).unwrap_or(&[]);
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(n)
    }
}

fn new_archive() -> Archive<&'static [u8]> {
    Archive::open(&[][..], OpenFlags(0)).unwrap()
}

fn streamed<R: hivepack_zip::ReadAt>(archive: &mut Archive<R>) -> Vec<u8> {
    let mut out = Pipe(Vec::new());
    assert_eq!(archive.close_to_stream(&mut out).unwrap(), Closed::Written);
    out.0
}

/// What each entry holds, read with every check there is, and how it is compressed.
fn read_back(bytes: &[u8], password: Option<&[u8]>) -> Vec<(String, u16, Vec<u8>)> {
    let mut archive = Archive::open(bytes, OpenFlags::CHECKCONS | OpenFlags::RDONLY).unwrap();
    archive.set_default_password(password);
    (0..archive.get_num_entries(Flags::NONE))
        .map(|i| {
            let st = archive.stat_index(i, Flags::NONE).unwrap();
            let name = String::from_utf8_lossy(st.name.unwrap()).into_owned();
            let method = st.comp_method;
            let mut body = Vec::new();
            io::copy(&mut archive.fopen_index(i, Flags::NONE).unwrap(), &mut body).unwrap();
            (name, method, body)
        })
        .collect()
}

/// The tools that are there find `bytes` sound. `password`, if the tool knows the
/// encryption.
fn tools_agree(bytes: &[u8], test: &str, password: Option<&str>) {
    let dir = std::env::temp_dir().join(format!("hivepack-stream-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let zip = dir.join("a.zip");
    std::fs::write(&zip, bytes).unwrap();
    let run = |tool: &Path, args: &[&str]| {
        let out = Command::new(tool)
            .args(args)
            .arg(&zip)
            .stdin(Stdio::null())
            .output();
        out.ok().map(|o| {
            let said = String::from_utf8_lossy(&o.stdout).into_owned()
                + &String::from_utf8_lossy(&o.stderr);
            assert!(o.status.success(), "{}: {said}", tool.display());
        })
    };
    if let Some(seven) = seven_zip() {
        let p = password.map(|p| format!("-p{p}")).unwrap_or_default();
        let mut args = vec!["t"];
        if !p.is_empty() {
            args.push(&p);
        }
        run(&seven, &args);
    }
    if password.is_none() {
        run(Path::new("unzip"), &["-t"]);
        let python = "import sys,zipfile; bad = zipfile.ZipFile(sys.argv[1]).testzip(); sys.exit(1 if bad else 0)";
        run(Path::new("python3"), &["-c", python]);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn what_compresses_what_does_not_and_what_is_empty() {
    let long = b"hello ".repeat(100_000);
    let wild = noise(300_000);
    let small_wild = noise(4_000);
    let mut archive = new_archive();
    for (name, body) in [
        ("long.txt", long.clone()),
        ("wild.bin", wild.clone()),
        ("small-wild.bin", small_wild.clone()),
        ("empty", Vec::new()),
        ("one", b"1".to_vec()),
    ] {
        archive
            .file_add(name.as_bytes(), BufferSource::new(body), Flags::NONE)
            .unwrap();
    }
    archive.dir_add(b"folder", Flags::NONE).unwrap();
    let bytes = streamed(&mut archive);
    let entries = read_back(&bytes, None);
    assert_eq!(entries.len(), 6);
    assert_eq!(entries[0].2, long);
    assert_eq!(entries[0].1, cm::DEFLATE);
    assert_eq!(entries[1].2, wild);
    assert_eq!(entries[1].1, cm::DEFLATE);
    // Compressing gave way to storing, and the header says what was done.
    assert_eq!(entries[2].2, small_wild);
    assert_eq!(entries[2].1, cm::STORE);
    assert_eq!(entries[3].2, b"");
    assert_eq!(entries[4].2, b"1");
    tools_agree(&bytes, "plain", None);
}

#[test]
fn it_holds_what_it_would_hold_written_with_seeking() {
    let body = b"the same either way ".repeat(5_000);
    let make = || {
        let mut archive = new_archive();
        archive
            .file_add(
                b"a",
                BufferSource::with_mtime(body.clone(), 1_700_000_000),
                Flags::NONE,
            )
            .unwrap();
        archive
    };
    let mut seeking = Cursor::new(Vec::new());
    make().close_to(&mut seeking).unwrap();
    let forwards = streamed(&mut make());
    assert_eq!(
        read_back(seeking.get_ref(), None),
        read_back(&forwards, None)
    );
    // Its descriptor, and nothing else, for the one entry: 16 bytes.
    assert_eq!(forwards.len(), seeking.get_ref().len() + 16);
}

#[test]
fn encrypted_entries() {
    let body = b"secret ".repeat(10_000);
    let mut archive = new_archive();
    // Windows has no system source without one, and salts need not be secret here.
    archive.set_random_source(Some(std::sync::Arc::new(|buffer: &mut [u8]| {
        buffer.fill(7);
        Ok(())
    })));
    for (name, method) in [
        ("aes", em::AES_256),
        ("short-aes", em::AES_128),
        ("old", em::TRAD_PKWARE),
    ] {
        let data = if name == "short-aes" {
            b"short".to_vec()
        } else {
            body.clone()
        };
        let i = archive
            .file_add(name.as_bytes(), BufferSource::new(data), Flags::NONE)
            .unwrap();
        archive
            .file_set_encryption(i, method, Some(b"pass".as_slice()))
            .unwrap();
    }
    let bytes = streamed(&mut archive);
    let entries = read_back(&bytes, Some(b"pass"));
    assert_eq!(entries[0].2, body);
    assert_eq!(entries[1].2, b"short");
    assert_eq!(entries[2].2, body);
    tools_agree(&bytes, "encrypted", Some("pass"));
}

#[test]
fn a_source_that_does_not_say_its_size_gets_zip64() {
    let body: Arc<[u8]> = b"how long? ".repeat(10_000).into();
    let mut archive = new_archive();
    archive
        .file_add(b"unsaid", NoSize(body.clone()), Flags::NONE)
        .unwrap();
    let bytes = streamed(&mut archive);
    assert_eq!(read_back(&bytes, None)[0].2, &*body);
    tools_agree(&bytes, "no-size", None);
}

#[test]
fn entries_kept_from_an_archive_are_copied_and_new_ones_follow() {
    let mut first = new_archive();
    first
        .file_add(
            b"kept",
            BufferSource::new(b"kept ".repeat(1000)),
            Flags::NONE,
        )
        .unwrap();
    let mut cursor = Cursor::new(Vec::new());
    first.close_to(&mut cursor).unwrap();
    let old = cursor.into_inner();
    let mut archive = Archive::open(old.as_slice(), OpenFlags::CHECKCONS).unwrap();
    archive
        .file_add(b"new", BufferSource::new(b"new ".repeat(1000)), Flags::NONE)
        .unwrap();
    let bytes = streamed(&mut archive);
    let entries = read_back(&bytes, None);
    assert_eq!(entries[0].2, b"kept ".repeat(1000));
    assert_eq!(entries[1].2, b"new ".repeat(1000));
    tools_agree(&bytes, "kept", None);
}

#[test]
fn torrentzip_has_no_way_forwards() {
    let mut archive = new_archive();
    archive
        .file_add(b"a", BufferSource::new(b"a".to_vec()), Flags::NONE)
        .unwrap();
    archive
        .set_archive_flag(hivepack_zip::ArchiveFlags::WANT_TORRENTZIP, true)
        .unwrap();
    let e = archive.close_to_stream(Pipe(Vec::new())).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Inval);
}

/// Over 4 GiB, written and read through by the tools: minutes without `--release`.
#[test]
#[ignore]
fn over_4_gib() {
    let piece: Arc<[u8]> = noise(1 << 20).into();
    struct Repeating(Arc<[u8]>, u64);
    impl DataSource for Repeating {
        fn stat(&self) -> hivepack_zip::Result<Stat<'static>> {
            let mut st = Stat::default();
            st.valid = stat::SIZE | stat::MTIME;
            st.size = self.1;
            st.mtime = 1_700_000_000;
            Ok(st)
        }
        fn file_attributes(&self) -> hivepack_zip::Result<FileAttributes> {
            Ok(FileAttributes::default())
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> hivepack_zip::Result<usize> {
            if offset >= self.1 {
                return Ok(0);
            }
            let at = (offset % self.0.len() as u64) as usize;
            let n = buf
                .len()
                .min(self.0.len() - at)
                .min((self.1 - offset) as usize);
            buf[..n].copy_from_slice(&self.0[at..at + n]);
            Ok(n)
        }
    }
    let dir = std::env::temp_dir().join(format!("hivepack-stream-big-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let zip = dir.join("big.zip");
    let mut archive = new_archive();
    archive
        .file_add(b"big", Repeating(piece, (4 << 30) + 12345), Flags::NONE)
        .unwrap();
    archive
        .file_add(b"after", BufferSource::new(b"after".to_vec()), Flags::NONE)
        .unwrap();
    let out = io::BufWriter::new(std::fs::File::create(&zip).unwrap());
    assert_eq!(archive.close_to_stream(out).unwrap(), Closed::Written);
    let seven = seven_zip().expect("7zz");
    let status = Command::new(seven)
        .arg("t")
        .arg(&zip)
        .stdout(Stdio::null())
        .status();
    assert!(status.unwrap().success());
    let python = "import sys,zipfile; bad = zipfile.ZipFile(sys.argv[1]).testzip(); sys.exit(1 if bad else 0)";
    let status = Command::new("python3")
        .args(["-c", python])
        .arg(&zip)
        .status();
    assert!(status.unwrap().success());
    let status = Command::new("unzip").arg("-tq").arg(&zip).status();
    assert!(status.unwrap().success());
    let _ = std::fs::remove_dir_all(&dir);
}
