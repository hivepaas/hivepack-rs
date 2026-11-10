//! What the comparison tests with the LZMA SDK and 7-Zip share: the oracle,
//! `7zz`, both built by `scripts/testdata.py`, a seeded generator, and files
//! to make archives of.

// Test helpers: a broken oracle or tool should stop the test.
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

pub fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Where `scripts/testdata.py` keeps what it fetches and generates.
pub fn cache() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"))
}

/// `folder` of the cache, if `scripts/testdata.py` made it; CI lists the
/// `generated` group in `HIVEPACK_TESTDATA_REQUIRED` where it does, and then
/// a missing one fails the test.
fn generated(folder: &str) -> Option<PathBuf> {
    let folder = cache().join(folder);
    if folder.join(".complete").exists() {
        return Some(folder);
    }
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    assert!(
        !required.split(',').any(|g| g == "all" || g == "generated"),
        "{} is missing: run `python3 scripts/testdata.py fetch --group generated`",
        folder.display()
    );
    eprintln!(
        "skipping: {} is not built (scripts/testdata.py fetch --group generated)",
        folder.display()
    );
    None
}

/// The oracle program, running.
pub struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    pub fn spawn() -> Option<Oracle> {
        let folder = generated("7z-oracle")?;
        let mut child = Command::new(folder.join("oracle"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the oracle starts");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        Some(Oracle {
            child,
            input,
            output,
        })
    }

    /// Its answer for the archive at `path`.
    pub fn ask(&mut self, path: &Path) -> String {
        writeln!(self.input, "archive {}", path.display()).expect("request sent");
        self.input.flush().expect("request sent");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("answer read");
        let line = line.trim_end().to_string();
        assert!(
            line != "bad" && !line.is_empty(),
            "the oracle answered {line:?} for {}",
            path.display()
        );
        line
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `7zz`, as `scripts/testdata.py` builds it.
pub fn seven_zip() -> Option<PathBuf> {
    Some(generated("7zz")?.join("7zz"))
}

/// A folder of the system's temporary one, emptied.
pub fn scratch(name: &str) -> PathBuf {
    let folder = std::env::temp_dir().join(format!("hivepack-7z-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir_all(&folder).expect("a scratch folder");
    folder
}

/// The archive `7zz` makes of the folder `files` in `dir`, with `options`.
pub fn make_archive(tool: &Path, dir: &Path, files: &str, options: &str) -> Vec<u8> {
    let out = dir.join("made.7z");
    let _ = std::fs::remove_file(&out);
    let status = Command::new(tool)
        .current_dir(dir)
        .args(["a", "-bd", "-bso0", "-bsp0", "-y"])
        .args(options.split_whitespace())
        .arg(&out)
        .arg(files)
        .stdout(Stdio::null())
        .status()
        .expect("7zz starts");
    assert!(status.success(), "7zz failed with {options}");
    let archive = std::fs::read(&out).expect("the archive");
    let _ = std::fs::remove_file(&out);
    archive
}

/// `s` in hexadecimal, `-` when empty.
pub fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hexadecimal"))
        .collect()
}

/// FNV-1a, as the oracle hashes.
pub fn fnv64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

/// xorshift64*, so that failures can be replayed.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.below(values.len() as u64) as usize]
    }
}

/// `len` bytes of one of several kinds: text, runs, noise, or code, with
/// the bytes branch converters look for.
pub fn input(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 16);
    match rng.below(6) {
        0 => {
            let words: [&[u8]; 8] = [
                b"the ", b"quick ", b"brown ", b"fox ", b"jumps ", b"over ", b"lazy ", b"dog\n",
            ];
            while data.len() < len {
                data.extend_from_slice(rng.pick(&words));
            }
        }
        1 => {
            while data.len() < len {
                let byte = rng.next() as u8;
                let run = 1 + rng.below(300) as usize;
                data.extend(std::iter::repeat_n(byte, run));
            }
        }
        2 => {
            while data.len() < len {
                data.push(rng.next() as u8);
            }
        }
        3 => {
            // x86: calls and jumps, with offsets near each other.
            while data.len() < len {
                match rng.below(4) {
                    0 => {
                        data.push(0xE8);
                        data.extend_from_slice(&(rng.below(0x8000) as u32).to_le_bytes());
                    }
                    1 => {
                        data.push(0xE9);
                        data.extend_from_slice(
                            &(0u32.wrapping_sub(rng.below(0x8000) as u32)).to_le_bytes(),
                        );
                    }
                    2 => {
                        data.extend_from_slice(&[0x0F, 0x80 + rng.below(16) as u8]);
                        data.extend_from_slice(&(rng.below(0x1000) as u32).to_le_bytes());
                    }
                    _ => {
                        for _ in 0..rng.below(12) {
                            data.push(rng.below(0x40) as u8 + 0x40);
                        }
                    }
                }
            }
        }
        4 => {
            // Words of 4 bytes, with the opcodes of RISC calls among them.
            while data.len() < len {
                let word = rng.next() as u32 & 0x00FF_FFFF;
                let top = rng.pick(&[0xEB, 0x94, 0x90, 0x48, 0x40, 0x7F, 0xF0, 0x12]);
                data.extend_from_slice(&(word | (top << 24)).to_le_bytes());
                if rng.below(3) == 0 {
                    data.extend_from_slice(&[0x01, 0x00, 0x00, top as u8]);
                }
            }
        }
        _ => {
            // Blocks repeated, far from each other.
            let block: Vec<u8> = (0..1 + rng.below(5000)).map(|_| rng.next() as u8).collect();
            while data.len() < len {
                if rng.below(2) == 0 {
                    data.extend_from_slice(&block);
                } else {
                    data.push(rng.next() as u8);
                }
            }
        }
    }
    data.truncate(len);
    data
}

/// Files under `dir/files`, a folder or two, empty ones too. Returns their
/// total size.
pub fn write_files(rng: &mut Rng, dir: &Path, count: usize, max: usize) -> usize {
    let root = dir.join("files");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("sub/deeper")).expect("folders");
    std::fs::create_dir_all(root.join("empty folder")).expect("folders");
    let mut total = 0;
    for i in 0..count {
        let len = match rng.below(5) {
            0 => 0,
            1 => rng.below(100) as usize,
            _ => rng.below(max as u64 + 1) as usize,
        };
        let name = match i % 3 {
            0 => format!("file{i}.bin"),
            1 => format!("sub/é file {i}.txt"),
            _ => format!("sub/deeper/{i}"),
        };
        std::fs::write(root.join(name), input(rng, len)).expect("a file");
        total += len;
    }
    total
}

/// `archive` with bytes changed: in its data, in the header with its
/// checksums made right again, or cut short.
pub fn damaged(rng: &mut Rng, archive: &[u8]) -> Vec<u8> {
    let mut bad = archive.to_vec();
    if bad.len() < 32 {
        return bad;
    }
    let le64 = |b: &[u8], at: usize| {
        let mut word = [0; 8];
        word.copy_from_slice(&b[at..at + 8]);
        u64::from_le_bytes(word)
    };
    let next_offset = le64(&bad, 12) as usize;
    let next_size = le64(&bad, 20) as usize;
    let header = 32 + next_offset;
    let valid = header <= bad.len() && header + next_size == bad.len();
    match rng.below(if valid && next_size > 0 { 7 } else { 3 }) {
        0 => {
            // Anywhere, the checksums then finding it, most of the time.
            let at = rng.below(bad.len() as u64) as usize;
            bad[at] ^= 1 << rng.below(8);
        }
        1 => {
            bad.truncate(rng.below(bad.len() as u64) as usize);
        }
        2 => {
            // More after the end, which the header does not count.
            bad.push(rng.next() as u8);
        }
        3 | 4 => {
            // In the packed data.
            if next_offset > 0 {
                let at = 32 + rng.below(next_offset as u64) as usize;
                bad[at] = rng.next() as u8;
            }
        }
        _ => {
            // In the header: its checksums made right, so that the parsing
            // sees it.
            for _ in 0..1 + rng.below(3) {
                let at = header + rng.below(next_size as u64) as usize;
                match rng.below(3) {
                    0 => bad[at] ^= 1 << rng.below(8),
                    1 => bad[at] = rng.pick(&[0, 1, 0x7F, 0x80, 0xFF]),
                    _ => bad[at] = rng.next() as u8,
                }
            }
            let crc = hivepack::deflate::crc32(0, &bad[header..header + next_size]);
            bad[28..32].copy_from_slice(&crc.to_le_bytes());
            let crc = hivepack::deflate::crc32(0, &bad[12..32]);
            bad[8..12].copy_from_slice(&crc.to_le_bytes());
        }
    }
    bad
}

/// Salts and IVs for the tests, where the system's are not at hand: Windows has
/// no `/dev/urandom`, and a program there gives its own.
pub fn random_source() -> hivepack::sevenz::RandomSource {
    let rng = std::sync::Mutex::new(Rng(0x7a37_7a37));
    std::sync::Arc::new(move |bytes: &mut [u8]| {
        let mut rng = rng.lock().unwrap();
        bytes.iter_mut().for_each(|b| *b = rng.next() as u8);
        Ok(())
    })
}
