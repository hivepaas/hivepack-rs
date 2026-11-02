//! Deflate64 entries, which libzip does not read: the port reads them with
//! hivepack::deflate's `Inflate9`, and must give back the data they were
//! made from, check their CRC-32 and length, and, with `ZIP_CHECKCONS`,
//! refuse bytes after the stream, as it does for deflate.
//!
//! The streams come from [`deflate64`], a small encoder of fixed-Huffman
//! blocks with what only Deflate64 has: length code 285 with 16 extra bits
//! (lengths up to 65,538), and distance codes 30 and 31 (up to 65,536 back).

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;

use hivepack::deflate::crc32;
use hivepack::zip::{Archive, ErrorCode, Flags, OpenFlags};

/// xorshift64*, so that failures can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Deflate64's length codes 257..285: base and extra bits.
const LENGTHS: [(u32, u32); 29] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 1),
    (13, 1),
    (15, 1),
    (17, 1),
    (19, 2),
    (23, 2),
    (27, 2),
    (31, 2),
    (35, 3),
    (43, 3),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 4),
    (115, 4),
    (131, 5),
    (163, 5),
    (195, 5),
    (227, 5),
    (3, 16),
];
/// Deflate64's distance codes 0..31: base and extra bits.
const DISTANCES: [(u32, u32); 32] = [
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 1),
    (7, 1),
    (9, 2),
    (13, 2),
    (17, 3),
    (25, 3),
    (33, 4),
    (49, 4),
    (65, 5),
    (97, 5),
    (129, 6),
    (193, 6),
    (257, 7),
    (385, 7),
    (513, 8),
    (769, 8),
    (1025, 9),
    (1537, 9),
    (2049, 10),
    (3073, 10),
    (4097, 11),
    (6145, 11),
    (8193, 12),
    (12289, 12),
    (16385, 13),
    (24577, 13),
    (32769, 14),
    (49153, 14),
];

/// Bits from the low bit of each byte, as deflate packs them.
#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    hold: u64,
    count: u32,
}

impl Bits {
    fn put(&mut self, value: u32, count: u32) {
        self.hold |= u64::from(value) << self.count;
        self.count += count;
        while self.count >= 8 {
            self.bytes.push(self.hold as u8);
            self.hold >>= 8;
            self.count -= 8;
        }
    }

    /// A Huffman code, its first bit the highest.
    fn code(&mut self, code: u32, len: u32) {
        self.put(code.reverse_bits() >> (32 - len), len);
    }

    /// The fixed code of literal/length symbol `symbol`.
    fn symbol(&mut self, symbol: u32) {
        match symbol {
            0..=143 => self.code(0x30 + symbol, 8),
            144..=255 => self.code(0x190 + symbol - 144, 9),
            256..=279 => self.code(symbol - 256, 7),
            _ => self.code(0xc0 + symbol - 280, 8),
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.count > 0 {
            self.put(0, 8 - self.count);
        }
        self.bytes
    }
}

/// A Deflate64 stream of one fixed-Huffman block, and its data: literals
/// and matches, long and far ones among them.
fn deflate64(rng: &mut Rng, len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut bits = Bits::default();
    let mut data = Vec::new();
    bits.put(1, 1); // the last block
    bits.put(1, 2); // fixed codes
    while data.len() < len {
        if data.is_empty() || rng.below(3) == 0 {
            let byte = b'a' + rng.below(20) as u8;
            bits.symbol(u32::from(byte));
            data.push(byte);
            continue;
        }
        let length = match rng.below(8) {
            0 => 259 + rng.below(65_280) as u32,
            _ => 3 + rng.below(256) as u32,
        };
        let reach = data.len().min(65_536) as u64;
        let distance = if rng.below(4) == 0 {
            reach as u32
        } else {
            1 + rng.below(reach) as u32
        };
        let code = if length > 258 || rng.below(10) == 0 {
            28
        } else {
            LENGTHS[..28]
                .iter()
                .rposition(|&(base, _)| base <= length)
                .unwrap()
        };
        let dcode = DISTANCES
            .iter()
            .rposition(|&(base, _)| base <= distance)
            .unwrap();
        bits.symbol(257 + code as u32);
        bits.put(length - LENGTHS[code].0, LENGTHS[code].1);
        bits.code(dcode as u32, 5);
        bits.put(distance - DISTANCES[dcode].0, DISTANCES[dcode].1);
        for _ in 0..length {
            data.push(data[data.len() - distance as usize]);
        }
    }
    bits.symbol(256);
    (bits.finish(), data)
}

/// An archive of one entry named "d64", with `stream` as its data,
/// compressed with `method`, and the CRC and size of `data`.
fn archive(method: u16, stream: &[u8], data: &[u8]) -> Vec<u8> {
    let crc = crc32(0, data);
    let mut header = Vec::new();
    for (v, n) in [
        (20u32, 2),
        (0, 2),
        (u32::from(method), 2),
        (0, 2),
        (0x5b21, 2),
        (crc, 4),
    ] {
        header.extend_from_slice(&v.to_le_bytes()[..n]);
    }
    header.extend_from_slice(&(stream.len() as u32).to_le_bytes());
    header.extend_from_slice(&(data.len() as u32).to_le_bytes());
    header.extend_from_slice(&3u16.to_le_bytes());
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&header);
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(b"d64");
    zip.extend_from_slice(stream);
    let cd_offset = zip.len() as u32;
    zip.extend_from_slice(b"PK\x01\x02\x14\x03");
    zip.extend_from_slice(&header);
    zip.extend_from_slice(&[0; 12]); // extra and comment lengths, disk, attributes
    zip.extend_from_slice(&0u32.to_le_bytes()); // the local header's offset
    zip.extend_from_slice(b"d64");
    let cd_size = zip.len() as u32 - cd_offset;
    zip.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    zip.extend_from_slice(&cd_size.to_le_bytes());
    zip.extend_from_slice(&cd_offset.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip
}

/// The entry read in pieces of growing sizes: the data, or the error.
fn read(zip: &[u8], flags: OpenFlags) -> hivepack::zip::Result<Vec<u8>> {
    let za = Archive::open(zip, flags)?;
    let mut zf = za.fopen_index(0, Flags::NONE)?;
    let mut data = Vec::new();
    let mut buf = vec![0; 100_000];
    let mut piece = 1;
    loop {
        let n = zf.fread(&mut buf[..piece])?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        piece = (piece * 2 + 1).min(buf.len());
    }
    zf.fclose()?;
    Ok(data)
}

#[test]
fn reads_deflate64_entries() {
    let mut rng = Rng(0x6400_0001);
    for _ in 0..200 {
        let len = rng.below(300_000) as usize;
        let (stream, data) = deflate64(&mut rng, len);
        let zip = archive(9, &stream, &data);
        for flags in [OpenFlags(0), OpenFlags::CHECKCONS] {
            let got = read(&zip, flags).unwrap();
            assert!(got == data, "{} bytes, not {}", got.len(), data.len());
        }
        // Through std::io::Read too.
        let za = Archive::open(&zip[..], OpenFlags::CHECKCONS).unwrap();
        let mut got = Vec::new();
        za.fopen(b"d64", Flags::NONE)
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert!(got == data);
        // Raw, the stream itself.
        let mut raw = Vec::new();
        za.fopen_index(0, Flags::COMPRESSED)
            .unwrap()
            .read_to_end(&mut raw)
            .unwrap();
        assert_eq!(raw, stream);
    }
}

#[test]
fn checks_deflate64_entries() {
    let mut rng = Rng(0x6400_0002);
    let (stream, data) = deflate64(&mut rng, 100_000);

    // A wrong CRC: the data, then the error.
    let mut zip = archive(9, &stream, &data);
    let crc_at = 14;
    zip[crc_at] ^= 1;
    let cd = zip.len() - 22 - (46 + 3);
    zip[cd + 16] ^= 1;
    assert_eq!(
        read(&zip, OpenFlags::CHECKCONS).map_err(|e| e.code()),
        Err(ErrorCode::Crc)
    );

    // Bytes after the stream: refused with ZIP_CHECKCONS only.
    let mut longer = stream.clone();
    longer.extend_from_slice(b"junk");
    let zip = archive(9, &longer, &data);
    assert!(read(&zip, OpenFlags(0)).unwrap() == data);
    let error = read(&zip, OpenFlags::CHECKCONS).unwrap_err();
    assert_eq!(error.code(), ErrorCode::Incons);
    assert_eq!(error.system(), 25);

    // Cut short: a length that does not match.
    let zip = archive(9, &stream[..stream.len() / 2], &data);
    assert!(read(&zip, OpenFlags(0)).is_err());

    // Not Deflate64 at all: zlib's data error.
    let zip = archive(9, &[0xff; 40], &data);
    assert_eq!(
        read(&zip, OpenFlags(0)).map_err(|e| (e.code(), e.system())),
        Err((ErrorCode::Zlib, -3))
    );
}

#[test]
fn damaged_deflate64_entries_do_not_panic() {
    let mut rng = Rng(0x6400_0003);
    for _ in 0..3000 {
        let len = rng.below(20_000) as usize;
        let (mut stream, data) = deflate64(&mut rng, len);
        for _ in 0..1 + rng.below(4) {
            if stream.is_empty() {
                break;
            }
            let at = rng.below(stream.len() as u64) as usize;
            match rng.below(3) {
                0 => stream[at] ^= 1 << rng.below(8),
                1 => stream.truncate(at),
                _ => stream.insert(at, rng.next() as u8),
            }
        }
        let zip = archive(9, &stream, &data);
        for flags in [OpenFlags(0), OpenFlags::CHECKCONS] {
            let _ = read(&zip, flags);
        }
    }
}
