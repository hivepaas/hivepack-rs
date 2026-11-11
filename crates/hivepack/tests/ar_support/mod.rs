//! What the ar tests share: the oracle program, built with libarchive by
//! `scripts/testdata.py`, libarchive's test archive, a seeded generator,
//! the archives the tests make, and the text forms of the requests and
//! answers.

// Test helpers: a broken oracle should stop the test.
#![allow(dead_code, clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

pub fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Where `scripts/testdata.py` puts what it fetches and builds.
pub fn testdata() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"))
}

/// Whether CI requires `group` (`HIVEPACK_TESTDATA_REQUIRED`).
fn required(group: &str) -> bool {
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    required.split(',').any(|g| g == "all" || g == group)
}

/// libarchive's ar test archive (the `libarchive-ar` set), or none with a
/// note when it is not made; CI lists the `core` group in
/// `HIVEPACK_TESTDATA_REQUIRED`, and then it must be there.
pub fn libarchive_archive() -> Option<Vec<u8>> {
    let folder = testdata().join("libarchive-ar");
    if !folder.join(".complete").exists() {
        assert!(
            !required("core"),
            "libarchive's ar archive is missing: run `python3 scripts/testdata.py fetch`"
        );
        eprintln!("skipping: libarchive's ar archive is not made");
        return None;
    }
    Some(std::fs::read(folder.join("ar.ar")).expect("the archive"))
}

/// The oracle program, running.
pub struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// `tools/ar-oracle` built by `scripts/testdata.py`, or `None` with a
    /// note when it has not been built. CI lists the `generated` group in
    /// `HIVEPACK_TESTDATA_REQUIRED` where it builds the oracles, and then a
    /// missing oracle fails the test.
    pub fn spawn() -> Option<Oracle> {
        let folder = testdata().join("ar-oracle");
        if !folder.join(".complete").exists() {
            assert!(
                !required("generated"),
                "the oracle is missing: run `python3 scripts/testdata.py fetch --group generated`"
            );
            eprintln!(
                "skipping: the oracle is not built (scripts/testdata.py fetch --group generated)"
            );
            return None;
        }
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

    pub fn ask(&mut self, request: &str) -> String {
        writeln!(self.input, "{request}").expect("request sent");
        self.input.flush().expect("request sent");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("answer read");
        let line = line.trim_end().to_string();
        assert!(
            !line.is_empty() && !line.contains("BAD"),
            "the oracle answered {line:.300} to {request:.200}"
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
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
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

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// A character for a name: mostly letters and digits, some punctuation,
/// spaces, slashes and backslashes, NULs and bytes past ASCII.
pub fn name_char(rng: &mut Rng) -> u8 {
    match rng.below(20) {
        0 => b' ',
        1 => b'/',
        2 => b'\\',
        3 => 0,
        4 => 0x80 | rng.below(0x80) as u8,
        5 => rng.pick(b".-_#`\t\n"),
        _ => rng.pick(b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEF.o"),
    }
}

/// A name of `n` characters for a file.
pub fn name(rng: &mut Rng, n: usize) -> Vec<u8> {
    let mut name: Vec<u8> = (0..n)
        .map(|_| {
            if rng.below(4) == 0 {
                name_char(rng)
            } else {
                rng.pick(b"abcdefghijklmnopqrstuvwxyz0123456789._-")
            }
        })
        .collect();
    if rng.below(3) > 0 {
        // Most names are plain.
        for b in &mut name {
            if !b.is_ascii_alphanumeric() && *b != b'.' && *b != b'_' {
                *b = b'x';
            }
        }
    }
    name
}

/// A numeric field of `width` characters holding `value` as text in
/// `radix`, left-aligned and padded with spaces as ar writes them; or,
/// some of the time, what ar does not write: spaces first, tabs, a digit
/// past the radix, other characters, all spaces, or more digits than fit.
pub fn field(rng: &mut Rng, width: usize, value: u64, radix: u32, odd: bool) -> Vec<u8> {
    let digits = match radix {
        8 => format!("{value:o}"),
        _ => format!("{value}"),
    };
    let mut text = digits.into_bytes();
    if odd {
        match rng.below(8) {
            0 => text.insert(0, b' '),
            1 => text.insert(0, b'\t'),
            2 => text.push(rng.pick(b"89x-+")),
            3 => text = Vec::new(),
            4 => text = (0..width).map(|_| rng.pick(b"0123456789")).collect(),
            5 => {
                let mut spaced = vec![b' '; 1 + rng.below(width as u64) as usize];
                spaced.extend(&text);
                text = spaced;
            }
            6 => text.insert(rng.below(text.len() as u64 + 1) as usize, rng.pick(b" x\t")),
            _ => text = (0..width).map(|_| name_char(rng)).collect(),
        }
    }
    text.truncate(width);
    text.resize(width, b' ');
    text
}

/// What an entry of a crafted archive is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A GNU name, `name/`.
    Gnu,
    /// A name without a slash, as BSD writes short ones.
    Plain,
    /// A GNU long name, `/<offset>` in the filename table.
    GnuLong,
    /// A BSD long name, `#1/<length>` before the data.
    BsdLong,
    /// The symbol table of a static library, `/`.
    Symbols,
    /// The GNU filename table, `//`.
    Table,
    /// Another special name: `/SYM64/`, `__.SYMDEF`, `ARFILENAMES/`.
    Special,
}

/// One header and what follows it: the data, and the padding byte.
struct Member {
    name: Vec<u8>,
    data: Vec<u8>,
    /// The size the header says, which may not be the data's.
    size: Option<u64>,
}

/// A 60-byte header for `name` (16 bytes, as it is, padded with spaces) and
/// `size`, its other fields random.
fn header(rng: &mut Rng, name: &[u8], size: u64, odd: bool) -> Vec<u8> {
    let mut h = name.to_vec();
    h.truncate(16);
    h.resize(16, b' ');
    let odd_field = |rng: &mut Rng| odd && rng.below(5) == 0;
    let o = odd_field(rng);
    let v = rng.pick(&[0, 1_700_000_000, 999_999_999_999, 315_532_800]);
    h.extend(field(rng, 12, v, 10, o));
    let o = odd_field(rng);
    let v = rng.pick(&[0, 1000, 999_999, 65_534]);
    h.extend(field(rng, 6, v, 10, o));
    let o = odd_field(rng);
    let v = rng.pick(&[0, 100, 999_999]);
    h.extend(field(rng, 6, v, 10, o));
    let o = odd_field(rng);
    let v = rng.pick(&[0o100644, 0o644, 0o100755, 0o40755, 0o7777_7777, 0o120777]);
    h.extend(field(rng, 8, v, 8, o));
    let o = odd_field(rng);
    h.extend(field(rng, 10, size, 10, o));
    if odd && rng.below(40) == 0 {
        h.extend(rng.pick(&[b"`x", b" \n", b"\n`"]));
    } else {
        h.extend(b"`\n");
    }
    h
}

/// An ar archive made here, with what libarchive's writers do not make:
/// the symbol tables of static libraries, GNU filename tables with their
/// separators and padding, right and wrong, two of them, long names of
/// both kinds pointing anywhere, names of spaces, NULs and slashes, fields
/// as ar never writes them, sizes that are not the data's, odd sizes with
/// their padding byte or without, and archives that end anywhere.
pub fn crafted(rng: &mut Rng) -> Vec<u8> {
    let odd = rng.below(3) == 0;
    let mut out = match rng.below(30) {
        0 => b"!<thin>\n".to_vec(),
        1 => b"!<arch>".to_vec(),
        _ => b"!<arch>\n".to_vec(),
    };
    let mut members: Vec<Member> = Vec::new();
    // The names of the filename table, and where each starts in it.
    let mut table: Vec<u8> = Vec::new();
    let mut offsets: Vec<usize> = Vec::new();
    let count = rng.below(9) as usize;
    let kinds: Vec<Kind> = (0..count)
        .map(|_| {
            rng.pick(&[
                Kind::Gnu,
                Kind::Gnu,
                Kind::Plain,
                Kind::GnuLong,
                Kind::GnuLong,
                Kind::BsdLong,
                Kind::BsdLong,
                Kind::Symbols,
                Kind::Table,
                Kind::Special,
            ])
        })
        .collect();
    // The long names first, so that the table can come before them.
    let long_names: Vec<Vec<u8>> = kinds
        .iter()
        .map(|_| {
            let len = rng.pick(&[1, 15, 16, 17, 40, 200]);
            name(rng, len)
        })
        .collect();
    for (kind, long) in kinds.iter().zip(&long_names) {
        if *kind == Kind::GnuLong {
            offsets.push(table.len());
            table.extend(long);
            match rng.below(10) {
                0 => table.extend(b"\\\n"),
                1 => table.push(b'\n'),
                2 => {}
                _ => table.extend(b"/\n"),
            }
        }
    }
    if !table.is_empty() || rng.below(10) == 0 {
        match rng.below(8) {
            0 => {}
            1 => table.push(b'`'),
            2 => table.push(0),
            3 => table.push(b'x'),
            _ => {
                if table.len() % 2 == 1 {
                    table.push(b'\n');
                }
            }
        }
        let tables = if rng.below(15) == 0 { 2 } else { 1 };
        for _ in 0..tables {
            members.push(Member {
                name: b"//".to_vec(),
                data: table.clone(),
                size: if rng.below(20) == 0 {
                    Some(rng.pick(&[0, 1 << 30, (1 << 30) + 1]))
                } else {
                    None
                },
            });
        }
    }
    let mut long_offsets = offsets.iter();
    for (kind, long) in kinds.into_iter().zip(long_names) {
        let data = {
            let len = rng.pick(&[0, 1, 2, 7, 60, 61, 300]);
            rng.bytes(len)
        };
        let size = if odd && rng.below(6) == 0 {
            Some(rng.pick(&[
                0,
                1,
                data.len() as u64 + 1,
                data.len() as u64 + 61,
                9_999_999_999,
            ]))
        } else {
            None
        };
        let member = match kind {
            Kind::Gnu => {
                let mut n = {
                    let len = rng.pick(&[0, 1, 5, 14, 15]) as usize;
                    name(rng, len)
                };
                n.push(b'/');
                Member {
                    name: n,
                    data,
                    size,
                }
            }
            Kind::Plain => Member {
                name: {
                    let len = rng.pick(&[0, 1, 5, 15, 16]) as usize;
                    name(rng, len)
                },
                data,
                size,
            },
            Kind::GnuLong => {
                let at = long_offsets.next().copied().unwrap_or(0);
                let at = match rng.below(10) {
                    0 => table.len() + rng.below(3) as usize,
                    1 => rng.below(table.len() as u64 + 1) as usize,
                    _ => at,
                };
                let n = match rng.below(15) {
                    0 => b"/9xyz".to_vec(),
                    1 => format!("/ {at}").into_bytes(),
                    _ => format!("/{at}").into_bytes(),
                };
                Member {
                    name: n,
                    data,
                    size,
                }
            }
            Kind::BsdLong => {
                let len = match rng.below(12) {
                    0 => 0,
                    1 => long.len() + data.len() + 1,
                    2 => (1 << 20) + 1,
                    _ => long.len(),
                };
                let mut all = long.clone();
                all.extend(&data);
                let size = size.or(Some(all.len() as u64));
                Member {
                    name: format!("#1/{len}").into_bytes(),
                    data: all,
                    size,
                }
            }
            Kind::Symbols => Member {
                name: b"/".to_vec(),
                data,
                size,
            },
            Kind::Table => Member {
                name: b"//".to_vec(),
                data: name(rng, 20),
                size,
            },
            Kind::Special => Member {
                name: rng
                    .pick(&[
                        &b"/SYM64/"[..],
                        b"__.SYMDEF",
                        b"__.SYMDEF SORTED",
                        b"ARFILENAMES/",
                        b"                ",
                        b"\0",
                        b"/0",
                    ])
                    .to_vec(),
                data,
                size,
            },
        };
        members.push(member);
    }
    if rng.below(3) == 0 {
        // Shuffled: a table after the names that use it.
        let n = members.len();
        for i in (1..n).rev() {
            let j = rng.below(i as u64 + 1) as usize;
            members.swap(i, j);
        }
    }
    for member in members {
        let size = member.size.unwrap_or(member.data.len() as u64);
        out.extend(header(rng, &member.name, size, odd));
        out.extend(&member.data);
        if member.data.len() % 2 == 1 {
            match rng.below(if odd { 4 } else { 40 }) {
                0 => {}
                1 => out.push(b'x'),
                _ => out.push(b'\n'),
            }
        }
    }
    match rng.below(10) {
        0 => {
            let n = 1 + rng.below(59) as usize;
            out.extend((0..n).map(|_| name_char(rng)));
        }
        1 => out.truncate(rng.below(out.len() as u64 + 1) as usize),
        _ => {}
    }
    out
}

/// The offsets of the headers of `archive`, as far as the sizes in them go.
fn headers(archive: &[u8]) -> Vec<usize> {
    let mut found = Vec::new();
    let mut at = 8;
    while at + 60 <= archive.len() {
        found.push(at);
        let size: u64 = std::str::from_utf8(&archive[at + 48..at + 58])
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let next = at as u64 + 60 + size + size % 2;
        if next > archive.len() as u64 {
            break;
        }
        at = next as usize;
    }
    found
}

/// `archive` damaged once to three times: a bit or byte in a header, a
/// field set to something else, a bit anywhere, cut short, bytes put in or
/// taken out, or bytes after the end.
pub fn damage(rng: &mut Rng, mut archive: Vec<u8>) -> Vec<u8> {
    for _ in 0..1 + rng.below(3) {
        let len = archive.len();
        let targets = headers(&archive);
        match rng.below(12) {
            0..=3 => {
                let Some(&base) = targets.get(rng.below(targets.len().max(1) as u64) as usize)
                else {
                    continue;
                };
                let at = base + rng.below(60) as usize;
                if at < len {
                    if rng.below(2) == 0 {
                        archive[at] ^= 1 << rng.below(8);
                    } else {
                        archive[at] = name_char(rng);
                    }
                }
            }
            4 | 5 => {
                let Some(&base) = targets.get(rng.below(targets.len().max(1) as u64) as usize)
                else {
                    continue;
                };
                let at = base + 16 + rng.below(42) as usize;
                let n = 1 + rng.below(12) as usize;
                let digit = rng.pick(b"0 97\t");
                for b in archive.iter_mut().skip(at).take(n) {
                    *b = if rng.below(4) == 0 {
                        name_char(rng)
                    } else {
                        digit
                    };
                }
            }
            6 => {
                if len > 0 {
                    let at = rng.below(len as u64) as usize;
                    archive[at] ^= 1 << rng.below(8);
                }
            }
            7 | 8 => {
                let at = rng.below(len as u64 + 1) as usize;
                archive.truncate(at);
            }
            9 => {
                let at = rng.below(len as u64 + 1) as usize;
                let n = 1 + rng.below(70) as usize;
                let more = rng.bytes(n);
                archive.splice(at..at, more);
            }
            10 => {
                if len > 0 {
                    let at = rng.below(len as u64) as usize;
                    let n = (1 + rng.below(8) as usize).min(len - at);
                    archive.drain(at..at + n);
                }
            }
            _ => {
                let n = 1 + rng.below(130) as usize;
                let more = rng.bytes(n);
                archive.extend(more);
            }
        }
    }
    archive
}
