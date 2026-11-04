//! What the extraction tests share: test archives written by hivepack::zip,
//! with bytes changed where it would not write them, a scratch folder, and
//! where the fetched test data is.

// Test helpers: a broken archive should stop the test.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hivepack::extract::{Limits, Options, Summary, extract_zip};
use hivepack::zip::{Archive, BufferSource, Flags, OpenFlags, cm, opsys};

/// The time the test entries have, an even number of seconds as MS-DOS
/// times are.
pub const MTIME: i64 = 1_600_000_000;

/// An entry of a test archive.
pub enum Entry<'a> {
    File(&'a [u8], &'a [u8]),
    /// A file with Unix mode bits, type included.
    Mode(&'a [u8], &'a [u8], u32),
    Dir(&'a [u8]),
    /// A directory with the test time.
    DirAt(&'a [u8]),
    Stored(&'a [u8], &'a [u8]),
}

/// An archive of `entries`, written by hivepack::zip.
pub fn zip(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut za = Archive::open(&[][..], OpenFlags(0)).unwrap();
    for entry in entries {
        match *entry {
            Entry::File(name, data) => {
                za.file_add(name, BufferSource::with_mtime(data, MTIME), Flags::NONE)
                    .unwrap();
            }
            Entry::Mode(name, data, mode) => {
                let i = za
                    .file_add(name, BufferSource::with_mtime(data, MTIME), Flags::NONE)
                    .unwrap();
                za.file_set_external_attributes(i, Flags::NONE, opsys::UNIX, mode << 16)
                    .unwrap();
            }
            Entry::Dir(name) => {
                za.dir_add(name, Flags::NONE).unwrap();
            }
            Entry::DirAt(name) => {
                let i = za.dir_add(name, Flags::NONE).unwrap();
                za.file_set_mtime(i, MTIME, Flags::NONE).unwrap();
            }
            Entry::Stored(name, data) => {
                let i = za
                    .file_add(name, BufferSource::with_mtime(data, MTIME), Flags::NONE)
                    .unwrap();
                za.set_file_compression(i, i32::from(cm::STORE), 0).unwrap();
            }
        }
    }
    let mut out = Cursor::new(Vec::new());
    za.close_to(&mut out).unwrap();
    out.into_inner()
}

/// A fresh folder for a test, removed when dropped.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new() -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "hivepack-extract-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// The destination inside it, not created yet.
    pub fn out(&self) -> PathBuf {
        self.0.join("out")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn extract(
    data: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    let archive = Archive::open(data, OpenFlags::CHECKCONS).unwrap();
    extract_zip(&archive, out, options)
}

/// The paths under `dir`, sorted, with `/` after directories.
pub fn listing(dir: &Path) -> Vec<String> {
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

pub fn limits(change: impl FnOnce(&mut Limits)) -> Options {
    let mut options = Options::default();
    change(&mut options.limits);
    options
}

/// The central directory entry at `index`, and where it starts.
pub fn central_entries(data: &[u8]) -> Vec<(usize, usize)> {
    let eocd = data.len() - 22;
    assert_eq!(&data[eocd..eocd + 4], b"PK\x05\x06");
    let count = u16::from_le_bytes([data[eocd + 10], data[eocd + 11]]) as usize;
    let mut at = u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let mut entries = Vec::new();
    for _ in 0..count {
        let len = |o: usize| u16::from_le_bytes([data[at + o], data[at + o + 1]]) as usize;
        let size = 46 + len(28) + len(30) + len(32);
        entries.push((at, size));
        at += size;
    }
    entries
}

/// Patches the uncompressed size of the entry at `index`, in its local
/// header and in the central directory.
pub fn patch_size(data: &mut [u8], index: usize, size: u32) {
    let (central, _) = central_entries(data)[index];
    data[central + 24..central + 28].copy_from_slice(&size.to_le_bytes());
    let local = u32::from_le_bytes(data[central + 42..central + 46].try_into().unwrap()) as usize;
    data[local + 22..local + 26].copy_from_slice(&size.to_le_bytes());
}

pub fn options(change: impl FnOnce(&mut Options)) -> Options {
    let mut options = Options::default();
    // Every system's names, as these tests were written for, wherever they run.
    options.name_rules = hivepack::extract::NameRules::Portable;
    change(&mut options);
    options
}

/// Where `scripts/testdata.py` puts what it fetches.
pub fn testdata() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata"))
}

/// Whether a missing set of `group` fails the test, as in CI, rather than
/// skips it.
pub fn required(group: &str) -> bool {
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    required.split(',').any(|g| g == "all" || g == group)
}

/// The repository's root.
pub fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// An .xz file's content.
pub fn xz_decode(data: &[u8]) -> Vec<u8> {
    use hivepack::xz::{Action, InBuffer, OutBuffer, Status, Stream};
    let mut stream = Stream::stream_decoder(u64::MAX, 0).unwrap();
    let mut out = Vec::new();
    let mut input = InBuffer::new(data);
    let mut piece = vec![0; 1 << 16];
    loop {
        let mut output = OutBuffer::new(&mut piece);
        let status = stream
            .code(&mut output, &mut input, Action::Finish)
            .unwrap();
        let written = output.pos;
        out.extend_from_slice(&piece[..written]);
        if status == Status::StreamEnd {
            return out;
        }
    }
}
