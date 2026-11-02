//! Archives the tests make themselves, with what libarchive's writers do
//! not make: crc headers with right and wrong checksums, afio's large
//! headers among odc ones, big-endian binary headers, garbage before
//! headers, hard links with their data on the first link or the last,
//! archives without a trailer, odd padding, and sizes and name lengths
//! past what the reader takes; RPM packages around them; and damage.

use super::Rng;

/// A cpio format, as the test writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Odc,
    Afio,
    Newc,
    Crc,
    BinLe,
    BinBe,
}

/// A header's fields, as numbers to write; too large ones lose their high
/// digits.
#[derive(Clone, Debug, Default)]
pub struct Fields {
    pub dev: u64,
    pub devminor: u64,
    pub ino: u64,
    pub mode: u64,
    pub uid: u64,
    pub gid: u64,
    pub nlink: u64,
    pub rdev: u64,
    pub rdevminor: u64,
    pub mtime: u64,
    pub namesize: u64,
    pub filesize: u64,
    pub check: u64,
    /// Upper-case hexadecimal digits, which libarchive reads too.
    pub upper: bool,
}

fn octal(out: &mut Vec<u8>, value: u64, width: usize) {
    for i in (0..width).rev() {
        out.push(b'0' + ((value >> (3 * i)) & 7) as u8);
    }
}

fn hexa(out: &mut Vec<u8>, value: u64, width: usize, upper: bool) {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    for i in (0..width).rev() {
        out.push(digits[((value >> (4 * i)) & 15) as usize]);
    }
}

/// The header of `kind` with `f`.
pub fn header(kind: Kind, f: &Fields) -> Vec<u8> {
    let mut h = Vec::new();
    match kind {
        Kind::Odc => {
            h.extend_from_slice(b"070707");
            for (v, w) in [
                (f.dev, 6),
                (f.ino, 6),
                (f.mode, 6),
                (f.uid, 6),
                (f.gid, 6),
                (f.nlink, 6),
                (f.rdev, 6),
                (f.mtime, 11),
                (f.namesize, 6),
                (f.filesize, 11),
            ] {
                octal(&mut h, v, w);
            }
        }
        Kind::Afio => {
            h.extend_from_slice(b"070727");
            hexa(&mut h, f.dev, 8, f.upper);
            hexa(&mut h, f.ino, 16, f.upper);
            h.push(b'm');
            octal(&mut h, f.mode, 6);
            hexa(&mut h, f.uid, 8, f.upper);
            hexa(&mut h, f.gid, 8, f.upper);
            hexa(&mut h, f.nlink, 8, f.upper);
            hexa(&mut h, f.rdev, 8, f.upper);
            hexa(&mut h, f.mtime, 16, f.upper);
            h.push(b'n');
            hexa(&mut h, f.namesize, 4, f.upper);
            // The flags and the size of extra data, which libarchive does
            // not read.
            hexa(&mut h, f.check & 0xffff, 4, f.upper);
            hexa(&mut h, f.check >> 16, 4, f.upper);
            h.push(b's');
            hexa(&mut h, f.filesize, 16, f.upper);
            h.push(b':');
        }
        Kind::Newc | Kind::Crc => {
            h.extend_from_slice(if kind == Kind::Newc {
                b"070701"
            } else {
                b"070702"
            });
            for v in [
                f.ino,
                f.mode,
                f.uid,
                f.gid,
                f.nlink,
                f.mtime,
                f.filesize,
                f.dev,
                f.devminor,
                f.rdev,
                f.rdevminor,
                f.namesize,
                f.check,
            ] {
                hexa(&mut h, v, 8, f.upper);
            }
        }
        Kind::BinLe | Kind::BinBe => {
            let words = [
                0o70707,
                f.dev,
                f.ino,
                f.mode,
                f.uid,
                f.gid,
                f.nlink,
                f.rdev,
                f.mtime >> 16,
                f.mtime,
                f.namesize,
                f.filesize >> 16,
                f.filesize,
            ];
            for w in words {
                let w = w as u16;
                if kind == Kind::BinLe {
                    h.extend_from_slice(&w.to_le_bytes());
                } else {
                    h.extend_from_slice(&w.to_be_bytes());
                }
            }
        }
    }
    h
}

/// How many bytes pad a name of `namesize` bytes after the header.
pub fn name_pad(kind: Kind, namesize: u64) -> u64 {
    match kind {
        Kind::Newc | Kind::Crc => 2u64.wrapping_sub(namesize) & 3,
        Kind::BinLe | Kind::BinBe => namesize & 1,
        Kind::Odc | Kind::Afio => 0,
    }
}

/// How many bytes pad data of `size` bytes.
pub fn data_pad(kind: Kind, size: u64) -> u64 {
    match kind {
        Kind::Newc | Kind::Crc => size.wrapping_neg() & 3,
        Kind::BinLe | Kind::BinBe => size & 1,
        Kind::Odc | Kind::Afio => 0,
    }
}

/// An entry to write.
#[derive(Clone, Debug, Default)]
pub struct Member {
    pub fields: Fields,
    /// The name's bytes, as many as written (its NUL included, if any).
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    /// The padding's bytes are not zeros.
    pub dirty_pad: bool,
    /// One byte of padding too many, or too few.
    pub pad_error: i8,
}

/// Writes `m` in `kind`.
pub fn write_member(out: &mut Vec<u8>, kind: Kind, m: &Member, rng: &mut Rng) {
    out.extend_from_slice(&header(kind, &m.fields));
    out.extend_from_slice(&m.name);
    let pad = |out: &mut Vec<u8>, n: u64, rng: &mut Rng| {
        for _ in 0..n {
            out.push(if m.dirty_pad { rng.next() as u8 } else { 0 });
        }
    };
    let n = name_pad(kind, m.name.len() as u64);
    pad(out, n, rng);
    out.extend_from_slice(&m.data);
    let mut n = data_pad(kind, m.data.len() as u64) as i64 + i64::from(m.pad_error);
    if n < 0 {
        out.pop();
        n = 0;
    }
    pad(out, n as u64, rng);
}

/// A name for a file: ASCII, long, UTF-8, or with odd bytes.
pub fn name(rng: &mut Rng) -> Vec<u8> {
    let len = match rng.below(8) {
        0 => 1 + rng.below(3),
        1 => 60 + rng.below(100),
        2 => 200 + rng.below(300),
        _ => 3 + rng.below(20),
    } as usize;
    let alphabets: [&[&str]; 4] = [
        &["a", "B", "z", "0", "9", "_", ".", "-"],
        &["a", "/", "b", " ", "~", "#", "\\", "%"],
        &["é", "ü", "ñ", "Ø", "ß", "中", "文", "😀"],
        &["\u{1}", "\u{7f}", "\t", "\n", "x", "070707", "TRAILER!!!"],
    ];
    let pick = rng.below(4) as usize;
    let mut out = Vec::new();
    while out.len() < len {
        let alphabet = alphabets[if rng.below(5) == 0 {
            rng.below(4) as usize
        } else {
            pick
        }];
        out.extend_from_slice(alphabet[rng.below(alphabet.len() as u64) as usize].as_bytes());
    }
    if rng.below(30) == 0 {
        // Bytes that are not UTF-8.
        out.push(0xff);
        out.push(0x80);
    }
    out
}

/// The largest value of a field of `kind` that holds a mode, an owner and
/// the like, and of its time.
fn limits(kind: Kind) -> (u64, u64) {
    match kind {
        Kind::Odc => (0o777777, 0o77777777777),
        Kind::Afio | Kind::Newc | Kind::Crc => (0xffff_ffff, 0xffff_ffff),
        Kind::BinLe | Kind::BinBe => (0xffff, 0xffff_ffff),
    }
}

/// A number up to `max`: small, typical, or at the limit.
fn number(rng: &mut Rng, max: u64) -> u64 {
    match rng.below(6) {
        0 => 0,
        1 => rng.below(10),
        2 => rng.below(70000).min(max),
        3 => max,
        4 => max - rng.below(3).min(max),
        _ => rng.next() & max,
    }
}

/// The trailer, or something like it.
fn trailer(kind: Kind, rng: &mut Rng) -> Member {
    let mut m = Member::default();
    m.fields.nlink = 1;
    m.name = b"TRAILER!!!\0".to_vec();
    match rng.below(14) {
        // With a byte other than NUL at its end, or a shorter name.
        0 => m.name[10] = b'x',
        1 => m.name.truncate(10),
        // A symbolic link, whose target is read first.
        2 => {
            m.fields.mode = 0o120777;
            m.data = b"target".to_vec();
        }
        3 => {
            m.fields.mode = 0o100644;
            m.data = b"data after the trailer".to_vec();
        }
        _ => {}
    }
    m.fields.namesize = m.name.len() as u64;
    m.fields.filesize = m.data.len() as u64;
    if kind == Kind::Afio && rng.below(2) == 0 {
        m.fields.mtime = rng.next();
    }
    m
}

/// Garbage to put before a header: bytes the search for one goes through,
/// with pieces of headers in it.
pub fn garbage(rng: &mut Rng) -> Vec<u8> {
    let len = match rng.below(6) {
        0 => 1 + rng.below(3),
        1 => 110 + rng.below(20),
        2 => 1000 + rng.below(70000),
        _ => rng.below(200),
    } as usize;
    let mut out = Vec::new();
    while out.len() < len {
        match rng.below(8) {
            0 => out.extend_from_slice(b"07070"),
            1 => out.extend_from_slice(b"070707"),
            2 => out.extend_from_slice(b"0707270"),
            3 => out.extend_from_slice(b"0000000"),
            4 => out.push(rng.pick(b"01277")),
            5 => out.push(0),
            _ => out.push(rng.next() as u8),
        }
    }
    out.truncate(len);
    out
}

/// A crafted cpio archive.
pub fn crafted(rng: &mut Rng) -> Vec<u8> {
    let kind = rng.pick(&[
        Kind::Odc,
        Kind::Afio,
        Kind::Newc,
        Kind::Crc,
        Kind::BinLe,
        Kind::BinBe,
    ]);
    crafted_kind(rng, kind)
}

/// A crafted cpio archive in `kind`.
pub fn crafted_kind(rng: &mut Rng, kind: Kind) -> Vec<u8> {
    let (max, max_time) = limits(kind);
    let upper = rng.below(4) == 0;
    let mut out = Vec::new();
    // Groups of hard links still to write: their fields, how many, and
    // whether the data is on the last.
    let mut next_ino = 1 + rng.below(1000);
    let count = rng.below(14);
    let mut i = 0;
    while i < count {
        i += 1;
        // afio's headers come among odc's.
        let this_kind = match kind {
            Kind::Odc if rng.below(4) == 0 => Kind::Afio,
            Kind::Afio if rng.below(3) == 0 => Kind::Odc,
            k => k,
        };
        let (max, max_time) = if this_kind == kind {
            (max, max_time)
        } else {
            limits(this_kind)
        };
        if rng.below(8) == 0 {
            out.extend(garbage(rng));
        }
        let mut f = Fields {
            dev: number(rng, max),
            devminor: number(rng, max),
            ino: next_ino,
            uid: number(rng, max),
            gid: number(rng, max),
            nlink: 1,
            mtime: match rng.below(4) {
                0 => rng.next() & max_time,
                1 => max_time,
                _ => 1_000_000_000 + rng.below(1_000_000_000),
            },
            upper,
            ..Fields::default()
        };
        if this_kind == Kind::Afio {
            f.ino = if rng.below(4) == 0 {
                rng.next()
            } else {
                next_ino
            };
            if rng.below(4) == 0 {
                // Before 1970, or far after.
                let any = rng.next();
                f.mtime = rng.pick(&[u64::MAX, (-86400i64) as u64, 1 << 40, any]);
            }
        }
        if kind == Kind::BinLe || kind == Kind::BinBe {
            f.ino &= 0xffff;
        }
        next_ino += 1;
        let perm = rng.below(0o10000);
        let mut data = Vec::new();
        let mut copies = 1;
        let mut data_on_last = false;
        match rng.below(16) {
            0..=4 => {
                f.mode = 0o100000 | perm;
                let size = match rng.below(6) {
                    0 => 0,
                    1 => 1 + rng.below(4),
                    2 => rng.below(3000),
                    _ => rng.below(300),
                };
                data = rng.bytes(size as usize);
            }
            5 => f.mode = 0o040000 | perm,
            6 | 7 => {
                f.mode = 0o120000 | perm;
                data = name(rng);
                match rng.below(12) {
                    0 => data.insert(data.len() / 2, 0),
                    1 => data.clear(),
                    2 => {
                        data = rng.bytes_below(3000);
                        data.extend(rng.bytes(2000));
                    }
                    _ => {}
                }
            }
            8 => {
                f.mode = rng.pick(&[0o020000, 0o060000]) | perm;
                f.rdev = number(rng, max);
                f.rdevminor = number(rng, max);
            }
            9 => f.mode = rng.pick(&[0o010000, 0o140000]) | perm,
            10..=12 => {
                // Hard links: data on the first, or on the last (newc).
                f.mode = 0o100000 | perm;
                copies = 2 + rng.below(3);
                f.nlink = match rng.below(5) {
                    0 => copies + 1,
                    1 => copies - 1,
                    _ => copies,
                };
                data_on_last = kind == Kind::Newc || kind == Kind::Crc || rng.below(4) == 0;
                data = rng.bytes_below(200);
                if rng.below(4) == 0 {
                    // A symbolic link with links.
                    f.mode = 0o120000 | perm;
                    data = name(rng);
                }
            }
            13 => {
                // A mode of any kind, a binary one from PWB/UNIX.
                f.mode = rng.next() & max;
                data = rng.bytes_below(50);
            }
            14 => {
                // More links than there are, on files of their own.
                f.mode = 0o100000 | perm;
                f.nlink = number(rng, max);
                data = rng.bytes_below(40);
            }
            _ => {
                f.mode = 0o100000 | perm;
                f.ino = rng.below(3);
                f.nlink = 2 + rng.below(2);
            }
        }
        let path = name(rng);
        for copy in 0..copies {
            let mut m = Member {
                fields: f.clone(),
                ..Member::default()
            };
            m.name = path.clone();
            if copy > 0 {
                m.name.extend_from_slice(format!(".{copy}").as_bytes());
            }
            m.name.push(0);
            let has_data = copies == 1 || (copy + 1 == copies) == data_on_last;
            if has_data {
                m.data = data.clone();
            }
            match rng.below(30) {
                // A name whose size leaves out its NUL, or says more.
                0 => {
                    m.name.pop();
                }
                1 => m.name.extend_from_slice(b"\0more"),
                2 => m.name.clear(),
                3 => m.name.insert(m.name.len() / 2, 0),
                _ => {}
            }
            m.fields.namesize = m.name.len() as u64;
            m.fields.filesize = m.data.len() as u64;
            m.fields.check = if kind == Kind::Crc && rng.below(3) != 0 {
                m.data
                    .iter()
                    .fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)))
                    .into()
            } else {
                rng.next() & 0xffff_ffff
            };
            m.dirty_pad = rng.below(4) == 0;
            if rng.below(25) == 0 {
                m.pad_error = rng.pick(&[-1, 1, 2]);
            }
            // Sizes and name lengths past what the reader takes, or past the
            // archive.
            match rng.below(40) {
                0 => m.fields.namesize = rng.pick(&[0x10_0000, 0x10_0001, max, max - 1]),
                1 => m.fields.filesize = rng.pick(&[max_time, 0x7fff_ffff, 0x10_0001, 1 << 32]),
                2 if this_kind == Kind::Afio => {
                    m.fields.filesize = rng.pick(&[u64::MAX, 1 << 63, i64::MAX as u64])
                }
                3 if rng.below(20) == 0 => {
                    // A symbolic link of 1 MiB, the most the reader takes,
                    // or a byte more.
                    m.fields.mode = 0o120777;
                    m.data = vec![b'l'; 0x10_0000 + rng.below(2) as usize];
                    m.fields.filesize = m.data.len() as u64;
                }
                4 => m.fields.filesize = m.data.len() as u64 + 1 + rng.below(5),
                _ => {}
            }
            write_member(&mut out, this_kind, &m, rng);
        }
    }
    // The end.
    match rng.below(8) {
        0 => {}
        1 => {
            // A trailer after garbage.
            out.extend(garbage(rng));
            let t = trailer(kind, rng);
            write_member(&mut out, kind, &t, rng);
        }
        _ => {
            let t = trailer(kind, rng);
            write_member(&mut out, kind, &t, rng);
        }
    }
    // Blocks padded with zeros, or more after the end.
    match rng.below(5) {
        0 => out.resize(out.len().div_ceil(512) * 512, 0),
        1 => out.extend(rng.bytes_below(300)),
        _ => {}
    }
    out
}

/// An RPM package's lead, now and then one libarchive does not take.
fn lead(rng: &mut Rng) -> Vec<u8> {
    let mut lead = vec![0xED, 0xAB, 0xEE, 0xDB];
    // The version, and the type: binary (0) or source (1), as a
    // big-endian number.
    lead.extend_from_slice(&[rng.pick(&[3, 4]), rng.below(2) as u8, 0, rng.pick(&[0, 1])]);
    if rng.below(12) == 0 {
        match rng.below(4) {
            0 => lead[4] = rng.pick(&[0, 2, 5]),
            1 => lead[6] = 1,
            2 => lead[7] = 2,
            _ => lead[3] = 0xDC,
        }
    }
    // The architecture, the name, the system and the signature type.
    lead.extend_from_slice(&[0, 1]);
    let mut name = b"hivepack-1.0-1".to_vec();
    name.resize(66, 0);
    lead.extend_from_slice(&name);
    lead.extend_from_slice(&[0, 1, 0, 5]);
    lead.resize(96, 0);
    lead
}

/// An RPM header of `entries` index entries and `bytes` bytes of data.
fn rpm_header(rng: &mut Rng, entries: u32, bytes: u32) -> Vec<u8> {
    let mut h = vec![0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0];
    h.extend_from_slice(&entries.to_be_bytes());
    h.extend_from_slice(&bytes.to_be_bytes());
    h.extend(rng.bytes(entries as usize * 16 + bytes as usize));
    h
}

/// A crafted RPM package around `payload`.
pub fn rpm(rng: &mut Rng, payload: &[u8]) -> Vec<u8> {
    let mut out = lead(rng);
    let headers = rng.pick(&[2, 2, 2, 1, 0, 3]);
    for i in 0..headers {
        let entries = rng.below(8) as u32;
        let bytes = rng.below(200) as u32;
        out.extend(rpm_header(rng, entries, bytes));
        if i == 0 || rng.below(3) == 0 {
            // The signature is padded to 8 bytes.
            while !out.len().is_multiple_of(8) {
                out.push(0);
            }
        }
        if rng.below(10) == 0 {
            out.extend(std::iter::repeat_n(0, rng.below(20) as usize));
        }
    }
    if rng.below(10) == 0 {
        // A header whose lengths go past the package.
        out.extend_from_slice(&[0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0]);
        out.extend_from_slice(&(rng.next() as u32).to_be_bytes());
        out.extend_from_slice(&(rng.next() as u32).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// A plain RPM package around `payload`: a lead, a signature and a header.
pub fn rpm_plain(payload: &[u8]) -> Vec<u8> {
    let mut rng = Rng(0x9a4c_a6e5);
    let mut out = vec![0xED, 0xAB, 0xEE, 0xDB, 3, 0, 0, 0];
    out.resize(96, 0);
    out.extend(rpm_header(&mut rng, 3, 21));
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    out.extend(rpm_header(&mut rng, 5, 100));
    out.extend_from_slice(payload);
    out
}

/// A payload for an RPM package: a cpio archive, compressed or not, or
/// what looks like a compressed one.
pub fn payload(rng: &mut Rng) -> Vec<u8> {
    match rng.below(6) {
        0 | 1 => {
            let kind = rng.pick(&[Kind::Newc, Kind::Crc, Kind::Odc]);
            crafted_kind(rng, kind)
        }
        2 => {
            let magic: &[u8] = rng.pick(&[
                &[0x1f, 0x8b, 0x08][..],
                b"BZh9",
                &[0xFD, b'7', b'z', b'X', b'Z', 0],
                &[0x28, 0xB5, 0x2F, 0xFD],
                &[0x5D, 0, 0, 0x80, 0],
            ]);
            let mut p = magic.to_vec();
            p.extend(rng.bytes_below(500));
            p
        }
        3 => {
            // Zeros first, which the filter takes as padding.
            let mut p = vec![0; 1 + rng.below(20) as usize];
            p.extend(crafted_kind(rng, Kind::Newc));
            p
        }
        4 => rng.bytes_below(30),
        _ => {
            // Another package inside.
            let inner = crafted_kind(rng, Kind::Newc);
            let mut p = rpm(rng, &inner);
            if rng.below(3) == 0 {
                p = rpm(rng, &p);
            }
            p
        }
    }
}

/// The offsets of what look like cpio headers: the targets of damage.
pub fn headers(archive: &[u8]) -> Vec<usize> {
    let mut at = Vec::new();
    for i in 0..archive.len().saturating_sub(5) {
        if archive[i..].starts_with(b"07070")
            || archive[i..].starts_with(&[0xc7, 0x71])
            || archive[i..].starts_with(&[0x71, 0xc7])
        {
            at.push(i);
        }
    }
    at
}

/// A digit, a letter, or anything, for a byte in a header.
fn character(rng: &mut Rng) -> u8 {
    match rng.below(6) {
        0 => b'0' + rng.below(8) as u8,
        1 => b'0' + rng.below(10) as u8,
        2 => rng.pick(b"abcdefABCDEF"),
        3 => rng.pick(b" gxGmns:!"),
        4 => 0,
        _ => rng.next() as u8,
    }
}

/// The archive (or package) with one to three things wrong in it.
pub fn damage(rng: &mut Rng, mut archive: Vec<u8>) -> Vec<u8> {
    for _ in 0..1 + rng.below(3) {
        let len = archive.len();
        let targets = headers(&archive);
        match rng.below(12) {
            // A bit or byte in a header.
            0..=3 => {
                let Some(&base) = targets.get(rng.below(targets.len().max(1) as u64) as usize)
                else {
                    continue;
                };
                let at = base + rng.below(130) as usize;
                if at < len {
                    if rng.below(2) == 0 {
                        archive[at] ^= 1 << rng.below(8);
                    } else {
                        archive[at] = character(rng);
                    }
                }
            }
            // A run of digits in a header: a field set to something else.
            4 | 5 => {
                let Some(&base) = targets.get(rng.below(targets.len().max(1) as u64) as usize)
                else {
                    continue;
                };
                let at = base + 6 + rng.below(100) as usize;
                let n = 1 + rng.below(16) as usize;
                let digit = rng.pick(b"0f7F9");
                for b in archive.iter_mut().skip(at).take(n) {
                    *b = if rng.below(4) == 0 {
                        character(rng)
                    } else {
                        digit
                    };
                }
            }
            // A bit or byte anywhere.
            6 => {
                if len > 0 {
                    let at = rng.below(len as u64) as usize;
                    archive[at] ^= 1 << rng.below(8);
                }
            }
            // Cut short.
            7 | 8 => {
                let at = rng.below(len as u64 + 1) as usize;
                archive.truncate(at);
            }
            // Bytes put in, or taken out.
            9 => {
                let at = rng.below(len as u64 + 1) as usize;
                let more = garbage(rng);
                archive.splice(at..at, more);
            }
            10 => {
                if len > 0 {
                    let at = rng.below(len as u64) as usize;
                    let n = (1 + rng.below(8) as usize).min(len - at);
                    archive.drain(at..at + n);
                }
            }
            // Bytes after the end.
            _ => {
                let more = rng.below(3000) as usize;
                if rng.below(2) == 0 {
                    archive.extend(rng.bytes(more));
                } else {
                    archive.extend(std::iter::repeat_n(0, more));
                }
            }
        }
    }
    archive
}
