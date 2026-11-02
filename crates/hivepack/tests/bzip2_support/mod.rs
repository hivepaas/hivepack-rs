//! What the comparison tests with libbzip2 share: the oracle program, built by
//! `scripts/testdata.py`, a seeded generator, and the text forms of their
//! requests and answers.

// Test helpers: a broken oracle should stop the test.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

pub fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
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
        let cache = std::env::var_os("HIVEPACK_TESTDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| repository().join("target/testdata"));
        let folder = cache.join("bzip2-oracle");
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
            line != "bad" && !line.is_empty() && !line.ends_with(" bad"),
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

/// Where `scripts/testdata.py` keeps what it fetches and generates.
pub fn cache() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"))
}

/// libbzip2's compressor, through the bzip2 crate: `data` as one stream.
pub fn c_compress(data: &[u8], block_size: u32, work_factor: u32) -> Vec<u8> {
    let mut strm = bzip2::Compress::new(bzip2::Compression::new(block_size), work_factor);
    let mut out = Vec::with_capacity(data.len() + data.len() / 50 + 1000);
    loop {
        let status = strm
            .compress_vec(
                &data[strm.total_in() as usize..],
                &mut out,
                bzip2::Action::Finish,
            )
            .expect("libbzip2 compresses");
        if status == bzip2::Status::StreamEnd {
            return out;
        }
        out.reserve(out.capacity());
    }
}

/// Inputs of many kinds for the compressor: text, random bytes from
/// alphabets of every size, runs around the lengths the first run-length
/// coding treats apart, periodic data that sends the main sort to the
/// fallback, and all 256 byte values. `len` is the length, about.
pub fn input(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 300);
    match rng.below(8) {
        0 => {
            let words: &[&[u8]] = &[
                b"the ",
                b"bzip2 ",
                b"block ",
                b"sorting ",
                b"of ",
                b"Burrows ",
                b"Wheeler ",
                b"and ",
                b"a ",
                b"Huffman ",
                b"coder\n",
                b"run, ",
                b"length ",
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
            // Runs of 1 to 6 and around 255, which the first coding cuts
            // at 255.
            while data.len() < len {
                let byte = rng.below(4) as u8;
                let run = match rng.below(3) {
                    0 => 1 + rng.below(6),
                    1 => 250 + rng.below(12),
                    _ => 1 + rng.below(1000),
                };
                data.resize(data.len() + run as usize, byte);
            }
        }
        3 => {
            let period = 1 + rng.below(40) as usize;
            let unit: Vec<u8> = (0..period).map(|_| rng.next() as u8).collect();
            while data.len() < len {
                data.extend_from_slice(&unit);
            }
        }
        4 => {
            // Periodic with a few changes: repetitive, but not quite.
            let period = 1 + rng.below(20) as usize;
            let unit: Vec<u8> = (0..period).map(|_| rng.below(3) as u8).collect();
            while data.len() < len {
                data.extend_from_slice(&unit);
                if rng.below(500) == 0 {
                    data.push(rng.next() as u8);
                }
            }
        }
        5 => {
            while data.len() < len {
                data.extend((0..=255u8).map(|b| if rng.below(2) == 0 { b } else { 255 - b }));
            }
        }
        6 => {
            // Random bytes with no two in a row the same.
            let mut last = 0u8;
            while data.len() < len {
                let byte = rng.next() as u8;
                if byte != last {
                    data.push(byte);
                    last = byte;
                }
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

/// `BZ2_rNums`, from randtable.c.
#[rustfmt::skip]
static R_NUMS: [u16; 512] = [
    619, 720, 127, 481, 931, 816, 813, 233, 566, 247,
    985, 724, 205, 454, 863, 491, 741, 242, 949, 214,
    733, 859, 335, 708, 621, 574, 73, 654, 730, 472,
    419, 436, 278, 496, 867, 210, 399, 680, 480, 51,
    878, 465, 811, 169, 869, 675, 611, 697, 867, 561,
    862, 687, 507, 283, 482, 129, 807, 591, 733, 623,
    150, 238, 59, 379, 684, 877, 625, 169, 643, 105,
    170, 607, 520, 932, 727, 476, 693, 425, 174, 647,
    73, 122, 335, 530, 442, 853, 695, 249, 445, 515,
    909, 545, 703, 919, 874, 474, 882, 500, 594, 612,
    641, 801, 220, 162, 819, 984, 589, 513, 495, 799,
    161, 604, 958, 533, 221, 400, 386, 867, 600, 782,
    382, 596, 414, 171, 516, 375, 682, 485, 911, 276,
    98, 553, 163, 354, 666, 933, 424, 341, 533, 870,
    227, 730, 475, 186, 263, 647, 537, 686, 600, 224,
    469, 68, 770, 919, 190, 373, 294, 822, 808, 206,
    184, 943, 795, 384, 383, 461, 404, 758, 839, 887,
    715, 67, 618, 276, 204, 918, 873, 777, 604, 560,
    951, 160, 578, 722, 79, 804, 96, 409, 713, 940,
    652, 934, 970, 447, 318, 353, 859, 672, 112, 785,
    645, 863, 803, 350, 139, 93, 354, 99, 820, 908,
    609, 772, 154, 274, 580, 184, 79, 626, 630, 742,
    653, 282, 762, 623, 680, 81, 927, 626, 789, 125,
    411, 521, 938, 300, 821, 78, 343, 175, 128, 250,
    170, 774, 972, 275, 999, 639, 495, 78, 352, 126,
    857, 956, 358, 619, 580, 124, 737, 594, 701, 612,
    669, 112, 134, 694, 363, 992, 809, 743, 168, 974,
    944, 375, 748, 52, 600, 747, 642, 182, 862, 81,
    344, 805, 988, 739, 511, 655, 814, 334, 249, 515,
    897, 955, 664, 981, 649, 113, 974, 459, 893, 228,
    433, 837, 553, 268, 926, 240, 102, 654, 459, 51,
    686, 754, 806, 760, 493, 403, 415, 394, 687, 700,
    946, 670, 656, 610, 738, 392, 760, 799, 887, 653,
    978, 321, 576, 617, 626, 502, 894, 679, 243, 440,
    680, 879, 194, 572, 640, 724, 926, 56, 204, 700,
    707, 151, 457, 449, 797, 195, 791, 558, 945, 679,
    297, 59, 87, 824, 713, 663, 412, 693, 342, 606,
    134, 108, 571, 364, 631, 212, 174, 643, 304, 329,
    343, 97, 430, 751, 497, 314, 983, 374, 822, 928,
    140, 206, 73, 263, 980, 736, 876, 478, 430, 305,
    170, 514, 364, 692, 829, 82, 855, 953, 676, 246,
    369, 970, 294, 750, 807, 827, 150, 790, 288, 923,
    804, 378, 215, 828, 592, 281, 565, 555, 710, 82,
    896, 831, 547, 261, 524, 462, 293, 465, 502, 56,
    661, 821, 976, 991, 658, 869, 905, 758, 745, 193,
    768, 550, 608, 933, 378, 286, 215, 979, 792, 961,
    61, 688, 793, 644, 986, 403, 106, 366, 905, 644,
    372, 567, 466, 434, 645, 210, 389, 550, 919, 135,
    780, 773, 635, 389, 707, 100, 626, 958, 165, 504,
    920, 176, 193, 713, 857, 265, 203, 50, 668, 108,
    645, 990, 626, 197, 510, 357, 358, 850, 858, 364,
    936, 638,
];

/// bzip2's CRC, as `BZ_UPDATE_CRC` computes it, finalised.
pub fn bz_crc(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
    }
    !crc
}

fn get_bit(bytes: &[u8], at: usize) -> u32 {
    u32::from(bytes[at / 8] >> (7 - at % 8)) & 1
}

fn set_bit(bytes: &mut [u8], at: usize, bit: u32) {
    let mask = 1 << (7 - at % 8);
    if bit == 0 {
        bytes[at / 8] &= !mask;
    } else {
        bytes[at / 8] |= mask;
    }
}

/// A valid randomised stream for `data`, as bzip2 0.9.0 and earlier wrote
/// them: `data`, a single block with no two bytes in a row the same (so
/// that the first run-length coding leaves it as it is, flipped bits and
/// all), has the low bit flipped where `BZ2_rNums` says, is compressed as
/// usual, and the block is then marked randomised, with the CRCs of
/// `data`.
pub fn randomised(data: &[u8], block_size: u32) -> Vec<u8> {
    let (mut r_n_to_go, mut r_t_pos) = (0, 0);
    let masked: Vec<u8> = data
        .iter()
        .map(|&byte| {
            if r_n_to_go == 0 {
                r_n_to_go = R_NUMS[r_t_pos];
                r_t_pos = (r_t_pos + 1) % 512;
            }
            r_n_to_go -= 1;
            byte ^ u8::from(r_n_to_go == 1)
        })
        .collect();
    let mut stream = c_compress(&masked, block_size, 0);
    let crc = bz_crc(data).to_be_bytes();
    // The block's CRC, then the randomised bit, after the stream's header
    // and the block's magic.
    stream[10..14].copy_from_slice(&crc);
    stream[14] |= 0x80;
    // The combined CRC, which for one block is the block's, in the last
    // 32 bits before the padding, after the end's 48-bit magic.
    let bits = stream.len() * 8;
    let magic = 0x1772_4538_5090u64;
    let pad = (0..8)
        .find(|pad| {
            let start = bits - pad - 80;
            (0..48).all(|i| get_bit(&stream, start + i) == ((magic >> (47 - i)) & 1) as u32)
        })
        .expect("the end of the stream");
    let start = bits - pad - 32;
    let crc = bz_crc(data);
    for i in 0..32 {
        set_bit(&mut stream, start + i, (crc >> (31 - i)) & 1);
    }
    stream
}
