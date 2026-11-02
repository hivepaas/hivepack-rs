//! What the comparison tests with liblz4 share: the oracle program, built by
//! `scripts/testdata.py`, liblz4's compressors through the lz4 crate, a
//! seeded generator, and the text forms of requests and answers.

// Test helpers: a broken oracle or compressor should stop the test.
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
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

/// The oracle program, running.
pub struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// The oracle built by `scripts/testdata.py`, or `None` with a note when
    /// it has not been built. CI lists the `generated` group in
    /// `HIVEPACK_TESTDATA_REQUIRED` where it builds the oracle, and then a
    /// missing oracle fails the test.
    pub fn spawn() -> Option<Oracle> {
        let folder = cache().join("lz4-oracle");
        if !folder.join(".complete").exists() {
            let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
            assert!(
                !required.split(',').any(|g| g == "all" || g == "generated"),
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
            line != "bad" && !line.is_empty(),
            "the oracle answered {line:?} to {request:.200}"
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

pub fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// An answer as the recorded file keeps it: as it is when short, else its
/// FNV-1a hash.
pub fn recorded_form(answer: &str) -> String {
    if answer.len() <= 160 {
        answer.to_string()
    } else {
        format!("fnv64:{:016x}", fnv64(answer.as_bytes()))
    }
}

/// The bytes the oracle fills an output buffer with before decoding.
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7 + 3) & 255) as u8).collect()
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

/// Bytes changed, bits flipped, cut short or lengthened.
pub fn damage(rng: &mut Rng, stream: &[u8]) -> Vec<u8> {
    let mut damaged = stream.to_vec();
    for _ in 0..1 + rng.below(3) {
        if damaged.is_empty() {
            break;
        }
        let at = rng.below(damaged.len() as u64) as usize;
        match rng.below(4) {
            0 => damaged[at] ^= 1 << rng.below(8),
            1 => damaged[at] = rng.next() as u8,
            2 => damaged.truncate(at),
            _ => damaged.insert(at, rng.next() as u8),
        }
    }
    damaged
}

/// Inputs of many kinds: text, random bytes from alphabets of every size,
/// runs, periodic data with short and long periods (the offsets the
/// decoder copies apart: 1 to 15, and 16 and more), and incompressible
/// bytes. `len` is the length.
pub fn input(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 300);
    match rng.below(7) {
        0 => {
            let words: &[&[u8]] = &[
                b"the ",
                b"lz4 ",
                b"block ",
                b"frame ",
                b"of ",
                b"literals ",
                b"match ",
                b"and ",
                b"a ",
                b"offset ",
                b"token\n",
                b"length, ",
                b"checksum ",
            ];
            while data.len() < len {
                data.extend_from_slice(rng.pick(words));
            }
        }
        1 => {
            let alphabet = 1 + rng.below(256);
            while data.len() < len {
                data.push(rng.below(alphabet) as u8);
            }
        }
        2 => {
            while data.len() < len {
                let byte = rng.below(4) as u8;
                let run = match rng.below(3) {
                    0 => 1 + rng.below(20),
                    1 => 250 + rng.below(30),
                    _ => 1 + rng.below(5000),
                };
                data.resize(data.len() + run as usize, byte);
            }
        }
        3 => {
            let period = 1 + rng.below(40) as usize;
            let unit: Vec<u8> = (0..period).map(|_| rng.next() as u8).collect();
            while data.len() < len {
                data.extend_from_slice(&unit);
                if rng.below(300) == 0 {
                    data.push(rng.next() as u8);
                }
            }
        }
        4 => {
            // Pieces repeated from far back: offsets up to 64 KB.
            while data.len() < len {
                if data.len() > 100 && rng.below(3) > 0 {
                    let back = 1 + rng.below(data.len().min(70_000) as u64) as usize;
                    let from = data.len() - back;
                    let run = 4 + rng.below(300) as usize;
                    for i in 0..run {
                        let byte = data[from + i];
                        data.push(byte);
                    }
                } else {
                    for _ in 0..1 + rng.below(40) {
                        data.push(rng.next() as u8);
                    }
                }
            }
        }
        5 => {
            while data.len() < len {
                data.extend((0..=255u8).map(|b| if rng.below(2) == 0 { b } else { 255 - b }));
            }
        }
        _ => {
            while data.len() < len {
                data.push(rng.next() as u8);
            }
        }
    }
    data.truncate(len);
    data
}

/// liblz4's block compressors: `LZ4_compress_fast` with an acceleration of
/// 1 or more, `LZ4_compress_HC` with a level of 0 or less taken as
/// `-level`... as the lz4 crate maps them: `level` 0 is
/// `LZ4_compress_default`, positive levels are `LZ4_compress_HC`, negative
/// ones `LZ4_compress_fast` with `-level` as the acceleration.
pub fn c_compress_block(data: &[u8], level: i32) -> Vec<u8> {
    let mode = match level {
        0 => lz4::block::CompressionMode::DEFAULT,
        l if l > 0 => lz4::block::CompressionMode::HIGHCOMPRESSION(l),
        l => lz4::block::CompressionMode::FAST(-l),
    };
    lz4::block::compress(data, Some(mode), false).expect("liblz4 compresses")
}

/// The settings of a frame liblz4 writes.
#[derive(Clone, Copy, Debug)]
pub struct FrameSettings {
    pub block_size: u32,
    pub independent: bool,
    pub block_checksum: bool,
    pub content_checksum: bool,
    pub content_size: bool,
    pub level: u32,
    pub auto_flush: bool,
    pub favor_dec_speed: bool,
}

impl FrameSettings {
    pub fn random(rng: &mut Rng) -> Self {
        FrameSettings {
            block_size: rng.pick(&[0, 4, 4, 5, 6, 7]),
            independent: rng.below(3) == 0,
            block_checksum: rng.below(3) == 0,
            content_checksum: rng.below(2) == 0,
            content_size: rng.below(3) == 0,
            level: rng.pick(&[0, 0, 1, 2, 3, 9, 12]),
            auto_flush: rng.below(4) == 0,
            favor_dec_speed: rng.below(4) == 0,
        }
    }
}

/// `data` in a frame, by liblz4's frame compressor through the lz4 crate,
/// written in pieces of random sizes so that blocks of every fill come
/// out.
pub fn c_compress_frame(rng: &mut Rng, data: &[u8], settings: FrameSettings) -> Vec<u8> {
    use lz4::liblz4::BlockChecksum;
    let block_size = match settings.block_size {
        4 => lz4::BlockSize::Max64KB,
        5 => lz4::BlockSize::Max256KB,
        6 => lz4::BlockSize::Max1MB,
        7 => lz4::BlockSize::Max4MB,
        _ => lz4::BlockSize::Default,
    };
    let mut builder = lz4::EncoderBuilder::new();
    builder
        .block_size(block_size)
        .block_mode(if settings.independent {
            lz4::BlockMode::Independent
        } else {
            lz4::BlockMode::Linked
        })
        .block_checksum(if settings.block_checksum {
            BlockChecksum::BlockChecksumEnabled
        } else {
            BlockChecksum::NoBlockChecksum
        })
        .checksum(if settings.content_checksum {
            lz4::ContentChecksum::ChecksumEnabled
        } else {
            lz4::ContentChecksum::NoChecksum
        })
        .level(settings.level)
        .auto_flush(settings.auto_flush)
        .favor_dec_speed(settings.favor_dec_speed);
    if settings.content_size {
        builder.content_size(data.len() as u64);
    }
    let mut encoder = builder.build(Vec::new()).expect("an encoder");
    let mut at = 0;
    while at < data.len() {
        let piece = (1 + rng.below(200_000) as usize).min(data.len() - at);
        encoder
            .write_all(&data[at..at + piece])
            .expect("liblz4 compresses");
        at += piece;
    }
    let (frame, result) = encoder.finish();
    result.expect("liblz4 ends the frame");
    frame
}
