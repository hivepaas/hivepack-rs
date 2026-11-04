//! Archives written an entry at a time by `Writer`, each entry's data read once
//! from a reader as it is added: read back here and, where they are there, by
//! `7zz`, Info-ZIP's `unzip` and Python's `zipfile`; and the same as `close_to`
//! writes from the same entries.

#![allow(clippy::unwrap_used)]

use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use hivepack::zip::{
    Archive, BufferSource, ErrorCode, Flags, NewEntry, OpenFlags, Writer, cm, em, opsys,
};

/// `7zz`, if `scripts/testdata.py` has fetched it.
fn seven_zip() -> Option<PathBuf> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata"));
    let tool = cache.join("7zz/7zz");
    tool.exists().then_some(tool)
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

/// A reader that gives its data in small pieces, and panics if read again once it
/// has said it ended: what a pipe, or an entry being read, is.
struct Once {
    data: Vec<u8>,
    at: usize,
    ended: bool,
}

impl Once {
    fn new(data: &[u8]) -> Once {
        Once {
            data: data.to_vec(),
            at: 0,
            ended: false,
        }
    }
}

impl Read for Once {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert!(!self.ended, "read again after its end");
        let n = buf.len().min(1000).min(self.data.len() - self.at);
        buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        self.ended = n == 0;
        Ok(n)
    }
}

/// An entry read back: its name, method, external attributes, time and data.
type Back = (String, u16, (u8, u32), i64, Vec<u8>);

/// What each entry holds, read with every check there is: its name, method,
/// external attributes, time and data.
fn read_back(bytes: &[u8], password: Option<&[u8]>) -> Vec<Back> {
    let mut archive = Archive::open(bytes, OpenFlags::CHECKCONS | OpenFlags::RDONLY).unwrap();
    archive.set_default_password(password);
    (0..archive.get_num_entries(Flags::NONE))
        .map(|i| {
            let st = archive.stat_index(i, Flags::NONE).unwrap();
            let name = String::from_utf8_lossy(st.name.unwrap()).into_owned();
            let attributes = archive
                .file_get_external_attributes(i, Flags::NONE)
                .unwrap();
            let mut body = Vec::new();
            io::copy(&mut archive.fopen_index(i, Flags::NONE).unwrap(), &mut body).unwrap();
            (name, st.comp_method, attributes, st.mtime, body)
        })
        .collect()
}

/// The tools that are there find `bytes` sound. `password`, if the tool knows the
/// encryption.
fn tools_agree(bytes: &[u8], test: &str, password: Option<&str>) {
    let dir = std::env::temp_dir().join(format!("hivepack-writer-{}-{test}", std::process::id()));
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

const MTIME: i64 = 1_700_000_000;

fn entry(name: &str, mode: Option<u32>, size: Option<u64>) -> NewEntry {
    let mut entry = NewEntry::new(name);
    entry.mtime = Some(MTIME);
    entry.mode = mode;
    entry.size = size;
    entry
}

#[test]
fn files_directories_and_links_come_back() {
    let long = b"hello ".repeat(100_000);
    let wild = noise(300_000);
    let small_wild = noise(4_000);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .add_directory(&entry("docs", Some(0o755), None))
        .unwrap();
    for (name, body, size) in [
        ("docs/long.txt", &long, Some(long.len() as u64)),
        ("wild.bin", &wild, None),
        ("small-wild.bin", &small_wild, Some(small_wild.len() as u64)),
        ("empty", &Vec::new(), Some(0)),
    ] {
        let read = writer
            .add_file(&entry(name, Some(0o644), size), &mut Once::new(body))
            .unwrap();
        assert_eq!(read, body.len() as u64, "{name}");
    }
    writer
        .add_symlink(&entry("docs/link", None, None), "long.txt")
        .unwrap();
    writer
        .add_file(&NewEntry::new("no-mode"), &mut &b"plain"[..])
        .unwrap();
    let bytes = writer.finish().unwrap().into_inner();

    let entries = read_back(&bytes, None);
    let names: Vec<&str> = entries.iter().map(|e| e.0.as_str()).collect();
    assert_eq!(
        names,
        [
            "docs/",
            "docs/long.txt",
            "wild.bin",
            "small-wild.bin",
            "empty",
            "docs/link",
            "no-mode"
        ]
    );
    let unix = |mode: u32| (opsys::UNIX, mode << 16);
    assert_eq!(entries[0].2, (opsys::UNIX, (0o040_755 << 16) | 0x10));
    assert_eq!(entries[1].4, long);
    assert_eq!(entries[1].1, cm::DEFLATE);
    assert_eq!(entries[1].2, unix(0o100_644));
    assert_eq!(entries[1].3, MTIME);
    assert_eq!(entries[2].4, wild);
    // Compressing gave way to storing what does not compress.
    assert_eq!(entries[3].4, small_wild);
    assert_eq!(entries[3].1, cm::STORE);
    assert_eq!(entries[4].4, b"");
    assert_eq!(entries[5].4, b"long.txt");
    assert_eq!(entries[5].1, cm::STORE);
    assert_eq!(entries[5].2, unix(0o120_777));
    assert_eq!(entries[6].4, b"plain");
    tools_agree(&bytes, "plain", None);
}

#[test]
fn it_is_what_close_to_writes() {
    let body = b"the same either way ".repeat(5_000);
    let mut archive = Archive::open(&[][..], OpenFlags(0)).unwrap();
    let i = archive
        .file_add(
            b"a",
            BufferSource::with_mtime(body.clone(), MTIME),
            Flags::ENC_UTF_8,
        )
        .unwrap();
    archive.file_set_mtime(i, MTIME, Flags::NONE).unwrap();
    let mut closed = Cursor::new(Vec::new());
    archive.close_to(&mut closed).unwrap();

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .add_file(
            &entry("a", None, Some(body.len() as u64)),
            &mut Once::new(&body),
        )
        .unwrap();
    assert_eq!(writer.finish().unwrap().into_inner(), closed.into_inner());
}

#[test]
fn a_size_not_told_is_zip64() {
    let body = b"x".repeat(10_000);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .add_file(&entry("a", None, None), &mut Once::new(&body))
        .unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    // The Zip64 extra field, first in the local header's, after the name `a`.
    let extra = u16::from_le_bytes([bytes[28], bytes[29]]);
    assert!(extra >= 20, "{extra}");
    assert_eq!(&bytes[31..33], [0x01, 0x00]);
    assert_eq!(read_back(&bytes, None)[0].4, body);
    tools_agree(&bytes, "zip64", None);
}

#[test]
fn methods_and_encryption_are_the_writers_to_set() {
    let body = b"secret ".repeat(10_000);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer.set_compression(i32::from(cm::STORE), 0);
    writer
        .add_file(&entry("stored", None, None), &mut Once::new(&body))
        .unwrap();
    writer.set_compression(i32::from(cm::DEFLATE), 9);
    writer.set_encryption(em::AES_256, b"pass word");
    writer
        .add_file(&entry("sealed", None, None), &mut Once::new(&body))
        .unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    let entries = read_back(&bytes, Some(b"pass word"));
    assert_eq!(entries[0].1, cm::STORE);
    assert_eq!(entries[0].4, body);
    assert_eq!(entries[1].4, body);
    tools_agree(&bytes, "sealed", Some("pass word"));
}

#[test]
fn a_name_is_taken_once() {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .add_file(&NewEntry::new("a"), &mut &b"1"[..])
        .unwrap();
    let e = writer
        .add_file(&NewEntry::new("a"), &mut &b"2"[..])
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Exists);
    let e = writer
        .add_file(&NewEntry::new(""), &mut &b"3"[..])
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Inval);
}

#[test]
fn a_reader_that_fails_fails_the_entry() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("broken"))
        }
    }
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let e = writer
        .add_file(&NewEntry::new("a"), &mut Broken)
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Read);
}
