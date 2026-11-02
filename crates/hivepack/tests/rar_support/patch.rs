// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! Copies of existing archives with something changed, for the comparison
//! with UnRAR and for fuzzing. Nothing here compresses: what goes in as packed
//! data is whatever the caller has, usually a fuzzer's bytes, so that damage
//! reaches what a damaged header's CRC would stop, and what no archive at hand
//! does (RAR 7's algorithm, long distances, every filter).
//!
//! A module of `tests/support` and of the `rar_unpack` target.

/// libarchive 3.8.10's `rar5_stored.rar`, BSD-2-Clause: its main header, its
/// file header without the fields that change, and its end header.
const MAIN: &[u8] =
    b"Rar!\x1a\x07\x01\x00\x33\x92\xb5\xe5\x0a\x01\x05\x06\x00\x05\x01\x01\x80\x80\x00";
const ATTRIBUTES: &[u8] = b"\xa4\x83\x02";
const NAME: &[u8] = b"helloworld.txt";
const FILE_EXTRA: &[u8] = b"\x0a\x03\x13\x7e\x0e\xab\x5b\x56\xe9\x0e\x1a";
const END: &[u8] = b"\x1d\x77\x56\x51\x03\x05\x04\x00";

/// libarchive 3.8.10's `rar.rar`, BSD-2-Clause: its signature and main header,
/// the name and attributes of its first file, and its end header.
const MAIN15: &[u8] = b"Rar!\x1a\x07\x00\xcf\x90\x73\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x00";
const NAME15: &[u8] = b"test.txt";
const ATTRIBUTES15: &[u8] = b"\xa4\x81\x00\x00";
const END15: &[u8] = b"\xc4\x3d\x7b\x00\x40\x07\x00";

fn crc32(data: &[u8]) -> u32 {
    hivepack::deflate::crc32(0, data)
}

fn put_vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// `rar5_stored.rar`'s file header with these fields changed.
fn put_file(out: &mut Vec<u8>, comp_info: u64, unp_size: u64, packed: &[u8]) {
    let mut body = vec![2, 3];
    put_vint(&mut body, FILE_EXTRA.len() as u64);
    put_vint(&mut body, packed.len() as u64);
    // Its flags: only the time, no CRC, so that no hash is checked.
    body.push(0);
    put_vint(&mut body, unp_size);
    body.extend_from_slice(ATTRIBUTES);
    put_vint(&mut body, comp_info);
    body.push(1);
    put_vint(&mut body, NAME.len() as u64);
    body.extend_from_slice(NAME);
    body.extend_from_slice(FILE_EXTRA);
    let mut header = Vec::new();
    put_vint(&mut header, body.len() as u64);
    header.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&header).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(packed);
}

/// `rar.rar`'s first file header with these fields changed.
fn put_file15(out: &mut Vec<u8>, dictionary: u16, solid: bool, unp_size: u32, packed: &[u8]) {
    put_file15_as(out, 29, dictionary, solid, unp_size, packed);
}

/// The same, with this version of the algorithm.
fn put_file15_as(
    out: &mut Vec<u8>,
    unp_ver: u8,
    dictionary: u16,
    solid: bool,
    unp_size: u32,
    packed: &[u8],
) {
    let flags = 0x8000 | dictionary << 5 | u16::from(solid) << 4;
    let size = 32 + NAME15.len() as u16;
    let mut body = vec![0x74];
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&size.to_le_bytes());
    body.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    body.extend_from_slice(&unp_size.to_le_bytes());
    body.push(3);
    // No file CRC to speak of, and its time.
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(b"\xb7\x76\xda\x3e");
    // The algorithm, and a method that is not stored.
    body.extend_from_slice(&[unp_ver, 0x33]);
    body.extend_from_slice(&(NAME15.len() as u16).to_le_bytes());
    body.extend_from_slice(ATTRIBUTES15);
    body.extend_from_slice(NAME15);
    out.extend_from_slice(&(crc32(&body) as u16).to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(packed);
}

/// A copy of `rar5_stored.rar`, or `rar.rar`, whose data is `input` from its
/// fourth byte, as compressed data. The first byte says the algorithm, for
/// RAR 5 (bit 0), the dictionary (bits 1 and 2, the smallest being below the
/// 256 KiB that UnRAR uses at least), whether a second entry goes on as solid
/// (bit 3), whether it is `rar.rar` (bit 4), whether only 4 KiB are to come out
/// (bit 5), whether the second entry asks for a larger dictionary (bit 6) and
/// whether for a smaller one (bit 7), and the next two where the second entry's
/// data starts.
pub fn with_packed_data(input: &[u8]) -> Vec<u8> {
    let options = input.first().copied().unwrap_or(0);
    let split = match input {
        [_, a, b, ..] => usize::from(*a) | usize::from(*b) << 8,
        _ => 0,
    };
    let packed = input.get(3..).unwrap_or(&[]);
    let (first, second) = packed.split_at(split.min(packed.len()));

    if options & 16 != 0 {
        let dictionary = u16::from(options >> 1 & 3);
        let more = u16::from(options >> 6 & 1) * 3;
        let dictionary_first = dictionary + u16::from(options >> 7) * 3;
        let unp_size = if options & 32 != 0 { 4096 } else { u32::MAX };
        let mut out = MAIN15.to_vec();
        if options & 8 != 0 {
            put_file15(&mut out, dictionary_first, false, unp_size, first);
            put_file15(&mut out, dictionary + more, true, unp_size, second);
        } else {
            put_file15(&mut out, dictionary, false, unp_size, packed);
        }
        out.extend_from_slice(END15);
        return out;
    }

    let version = u64::from(options & 1);
    let dictionary = u64::from(options >> 1 & 3);
    let method = 3;
    let comp_info = version | method << 7 | dictionary << 10;
    let more = u64::from(options >> 6 & 1) * 3;
    let dictionary_first = u64::from(options >> 7) * 3;
    // By default more than can come out, as no size is what stops it here.
    let unp_size = if options & 32 != 0 { 4096 } else { 1 << 40 };

    let mut out = MAIN.to_vec();
    if options & 8 != 0 {
        put_file(
            &mut out,
            comp_info + (dictionary_first << 10),
            unp_size,
            first,
        );
        put_file(
            &mut out,
            (comp_info + (more << 10)) | 1 << 6,
            unp_size,
            second,
        );
    } else {
        put_file(&mut out, comp_info, unp_size, packed);
    }
    out.extend_from_slice(END);
    out
}

/// A copy of `rar.rar` with `input` from its fifth byte as data compressed by
/// RAR 1.5 or 2.x, with entries going on from each other as only these can. The
/// first byte says the algorithm (bits 0 and 1), the dictionary (bits 2 and 3),
/// whether a second entry follows (bit 4), whether the archive is solid (bit 5),
/// whether only 4 KiB are to come out (bit 6) and whether the second entry says
/// it is solid (bit 7), and the next two where the second entry's data starts.
/// The fourth says what the second entry's algorithm is (bits 0 and 1, the same
/// first) and how much larger its dictionary (bits 2 and 3).
pub fn with_old_packed_data(input: &[u8]) -> Vec<u8> {
    const ALGORITHMS: [u8; 4] = [15, 20, 26, 13];
    const SECOND: [u8; 4] = [0, 15, 20, 29];
    let options = input.first().copied().unwrap_or(0);
    let split = match input {
        [_, a, b, ..] => usize::from(*a) | usize::from(*b) << 8,
        _ => 0,
    };
    let more = input.get(3).copied().unwrap_or(0);
    let packed = input.get(4..).unwrap_or(&[]);
    let (first, second) = packed.split_at(split.min(packed.len()));

    let algorithm = ALGORITHMS[usize::from(options & 3)];
    let dictionary = u16::from(options >> 2 & 3);
    let unp_size = if options & 64 != 0 { 4096 } else { u32::MAX };

    // `MAIN15` with the archive's solid flag.
    let mut main = vec![0x73];
    main.extend_from_slice(&(u16::from(options & 32 != 0) << 3).to_le_bytes());
    main.extend_from_slice(&MAIN15[12..20]);
    let mut out = MAIN15[..7].to_vec();
    out.extend_from_slice(&(crc32(&main) as u16).to_le_bytes());
    out.extend_from_slice(&main);

    if options & 16 != 0 {
        put_file15_as(&mut out, algorithm, dictionary, false, unp_size, first);
        let chosen = SECOND[usize::from(more & 3)];
        let later = if chosen == 0 { algorithm } else { chosen };
        let dictionary = dictionary + u16::from(more >> 2 & 3);
        put_file15_as(
            &mut out,
            later,
            dictionary,
            options & 128 != 0,
            unp_size,
            second,
        );
    } else {
        put_file15_as(&mut out, algorithm, dictionary, false, unp_size, packed);
    }
    out.extend_from_slice(END15);
    out
}

/// `MAIN` with its locator saying the QuickOpen record is at `offset` from the
/// main header, in the three bytes RAR leaves for that or in all ten.
fn main_with_locator(offset: u64, long: bool) -> Vec<u8> {
    let mut extra = vec![1, 1];
    if long {
        let mut value = offset;
        for _ in 0..9 {
            extra.push(value as u8 | 0x80);
            value >>= 7;
        }
        extra.push(value as u8 & 1);
    } else {
        extra.push(offset as u8 | 0x80);
        extra.push((offset >> 7) as u8 | 0x80);
        extra.push((offset >> 14) as u8 & 0x7f);
    }
    let mut body = vec![1, 5];
    put_vint(&mut body, extra.len() as u64 + 1);
    body.push(0);
    put_vint(&mut body, extra.len() as u64);
    body.extend_from_slice(&extra);
    let mut header = Vec::new();
    put_vint(&mut header, body.len() as u64);
    header.extend_from_slice(&body);
    let mut out = MAIN[..8].to_vec();
    out.extend_from_slice(&crc32(&header).to_le_bytes());
    out.extend_from_slice(&header);
    out
}

/// A service header called `name`, encrypted with these rounds if any: a
/// record with no salt or start worth anything, as nothing here encrypts.
fn put_service(out: &mut Vec<u8>, name: &[u8], unp_size: u64, data: &[u8], rounds: Option<u8>) {
    let mut extra = Vec::new();
    if let Some(rounds) = rounds {
        extra.extend_from_slice(&[35, 1, 0, 0, rounds]);
        extra.extend((0..32).map(|i| i * 7 + rounds));
    }
    let mut body = vec![3, if extra.is_empty() { 2 } else { 3 }];
    if !extra.is_empty() {
        put_vint(&mut body, extra.len() as u64);
    }
    put_vint(&mut body, data.len() as u64);
    body.push(0);
    put_vint(&mut body, unp_size);
    body.extend_from_slice(&[0, 0, 1]);
    put_vint(&mut body, name.len() as u64);
    body.extend_from_slice(name);
    body.extend_from_slice(&extra);
    let mut header = Vec::new();
    put_vint(&mut header, body.len() as u64);
    header.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&header).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
}

/// A block of a QuickOpen record: a copy of `header` that belongs `offset`
/// before the record's header.
fn put_quick_open_item(out: &mut Vec<u8>, offset: u64, header: &[u8], good_crc: bool) {
    let mut body = Vec::new();
    body.push(0);
    put_vint(&mut body, offset);
    put_vint(&mut body, header.len() as u64);
    body.extend_from_slice(header);
    let mut block = Vec::new();
    put_vint(&mut block, body.len() as u64);
    block.extend_from_slice(&body);
    let crc = crc32(&block);
    out.extend_from_slice(&(if good_crc { crc } else { !crc }).to_le_bytes());
    out.extend_from_slice(&block);
}

/// A copy of `rar5_stored.rar` with a QuickOpen record, whose copies of headers
/// `input` says, so that they get past the record's CRCs and need not say what
/// the headers they stand for say.
///
/// The first byte says where the locator points (bits 0 to 2: 0 to 2 the record,
/// 3 the record called something else, 4 a second main header that points to the
/// record, 5 the file's header, 6 past the end and 7 further than a file can
/// be), whether the record's header says it is encrypted (bit 3),
/// whether its size says less or more than there is (bits 4 and 5) and how many
/// rounds its keys take (bits 6 and 7). Then each block has a byte saying what
/// it is, in its low 3 bits, with what follows:
///
/// - 0: a true copy of the main header (higher bits 0), the file's or the end's
/// - 1: the file's header with another size, and a name of the higher bits' length
/// - 2: an offset of 2 bytes, a size of 1 and that many bytes
/// - 3: a size in units of 256, of 11 bits, of zeros that end where the archive
///   starts, so that they are read past, or over the file's header if the higher
///   bits are odd. The last two sizes are too large for a block's size to say
/// - 4: a true copy of the file's header with a wrong CRC
/// - 5: a block of no size, or if the higher bits are not 0 one whose size does
///   not end, either of which ends it all
/// - 6: a service header standing for the file's, encrypted if the higher bits are
/// - 7: a byte's worth of what follows, as it is
pub fn with_quick_open(input: &[u8]) -> Vec<u8> {
    let options = input.first().copied().unwrap_or(0);
    let rounds = [1, 2, 3, 25][usize::from(options >> 6)];
    let long = options & 7 == 7;

    let mut file = Vec::new();
    put_file(&mut file, 0, 11, b"hello world");
    let main_len = main_with_locator(0, long).len() - 8;
    let file_pos = 8 + main_len;
    let mut qo_pos = file_pos + file.len();
    let second_main = options & 7 == 4;
    if second_main {
        qo_pos += main_len;
    }
    let main = main_with_locator(0, long);
    let file_header_len = file.len() - 11;

    let mut record = Vec::new();
    let mut at = 1;
    let next = |at: &mut usize| {
        let byte = input.get(*at).copied().unwrap_or(0);
        *at += 1;
        byte
    };
    while at < input.len() {
        let op = next(&mut at);
        let high = op >> 3;
        let to_file = (qo_pos - file_pos) as u64;
        match op & 7 {
            0 => match high {
                0 => put_quick_open_item(&mut record, qo_pos as u64 - 8, &main[8..], true),
                1 => {
                    put_quick_open_item(&mut record, to_file, &file[..file_header_len], true);
                }
                _ => put_quick_open_item(&mut record, 0, END, true),
            },
            1 => {
                let size = u64::from(next(&mut at));
                let name = &NAME[..usize::from(high).min(NAME.len())];
                let mut body = vec![2, 3];
                put_vint(&mut body, FILE_EXTRA.len() as u64);
                put_vint(&mut body, 11);
                body.push(0);
                put_vint(&mut body, size);
                body.extend_from_slice(ATTRIBUTES);
                body.extend_from_slice(&[0, 1]);
                put_vint(&mut body, name.len() as u64);
                body.extend_from_slice(name);
                body.extend_from_slice(FILE_EXTRA);
                let mut header = Vec::new();
                put_vint(&mut header, body.len() as u64);
                header.extend_from_slice(&body);
                let mut copy = crc32(&header).to_le_bytes().to_vec();
                copy.extend_from_slice(&header);
                put_quick_open_item(&mut record, to_file, &copy, true);
            }
            2 => {
                let offset = u64::from(next(&mut at)) | u64::from(next(&mut at)) << 8;
                let size = usize::from(next(&mut at));
                let end = (at + size).min(input.len());
                put_quick_open_item(&mut record, offset, &input[at.min(end)..end], true);
                at = end;
            }
            3 => {
                let size = usize::from(next(&mut at)) | usize::from(next(&mut at) & 7) << 8;
                let size = match size {
                    0x7fe => 0x20_0000,
                    0x7ff => 0x20_0001,
                    _ => size * 256,
                };
                let zeros = vec![0; size];
                let offset = if high & 1 != 0 {
                    to_file
                } else {
                    qo_pos as u64 + size as u64
                };
                put_quick_open_item(&mut record, offset, &zeros, true);
            }
            4 => {
                put_quick_open_item(&mut record, to_file, &file[..file_header_len], false);
            }
            5 if high == 0 => record.extend_from_slice(&[0; 7]),
            5 => record.extend_from_slice(&[0, 0, 0, 0, 0x80, 0x80, 0x80]),
            6 => {
                let mut copy = Vec::new();
                let chosen = (high != 0).then_some(rounds);
                put_service(&mut copy, b"CMT", 0, &[], chosen);
                put_quick_open_item(&mut record, to_file, &copy, true);
            }
            _ => {
                let end = (at + usize::from(high)).min(input.len());
                record.extend_from_slice(&input[at.min(end)..end]);
                at = end;
            }
        }
    }

    let mut out = Vec::new();
    let offset = match options & 7 {
        4 => (file_pos + file.len()) as u64 - 8,
        5 => file_pos as u64 - 8,
        6 => 1 << 20,
        7 => 1 << 63,
        _ => qo_pos as u64 - 8,
    };
    out.extend_from_slice(&main_with_locator(offset, long));
    out.extend_from_slice(&file);
    if second_main {
        let main_pos = file_pos + file.len();
        out.extend_from_slice(&main_with_locator((qo_pos - main_pos) as u64, false)[8..]);
    }
    let size = record.len() as u64;
    let unp_size = match options >> 4 & 3 {
        0 | 3 => size,
        1 => size / 2,
        _ => size * 2,
    };
    let chosen = (options & 8 != 0).then_some(rounds);
    let name: &[u8] = if options & 7 == 3 { b"CMT" } else { b"QO" };
    put_service(&mut out, name, unp_size, &record, chosen);
    out.extend_from_slice(END);
    out
}

/// What an entry of [`with_entries`] is.
#[derive(Clone, Copy)]
pub enum Kind<'a> {
    File,
    Dir,
    /// RAR 5's redirection, by its type, to this target. In RAR 4, a Unix link
    /// whose data is the target, whatever the type.
    Redirect(u64, &'a [u8]),
}

/// An entry of [`with_entries`]: stored, as nothing here compresses. Its CRC is
/// right unless it says otherwise.
#[derive(Clone, Copy)]
pub struct Entry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub kind: Kind<'a>,
    pub unix: bool,
    pub bad_crc: bool,
}

impl<'a> Entry<'a> {
    pub fn file(name: &'a [u8], data: &'a [u8]) -> Entry<'a> {
        Entry {
            name,
            data,
            kind: Kind::File,
            unix: true,
            bad_crc: false,
        }
    }
    pub fn dir(name: &'a [u8]) -> Entry<'a> {
        Entry {
            kind: Kind::Dir,
            ..Entry::file(name, b"")
        }
    }
    pub fn redirect(name: &'a [u8], kind: u64, target: &'a [u8]) -> Entry<'a> {
        Entry {
            kind: Kind::Redirect(kind, target),
            ..Entry::file(name, b"")
        }
    }
}

/// A copy of `rar5_stored.rar` with these entries in place of its one.
pub fn with_entries(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut out = MAIN.to_vec();
    for entry in entries {
        let mut extra = Vec::new();
        if let Kind::Redirect(kind, target) = entry.kind {
            let mut record = vec![5];
            put_vint(&mut record, kind);
            record.push(0);
            put_vint(&mut record, target.len() as u64);
            record.extend_from_slice(target);
            put_vint(&mut extra, record.len() as u64);
            extra.extend_from_slice(&record);
        }
        let is_dir = matches!(entry.kind, Kind::Dir);
        let mut body = vec![2, 2 | u8::from(!extra.is_empty())];
        if !extra.is_empty() {
            put_vint(&mut body, extra.len() as u64);
        }
        put_vint(&mut body, entry.data.len() as u64);
        body.push(4 | u8::from(is_dir));
        put_vint(&mut body, entry.data.len() as u64);
        let attr = match (entry.unix, entry.kind) {
            (true, Kind::File) => 0o100_644,
            (true, Kind::Dir) => 0o040_755,
            (true, Kind::Redirect(..)) => 0o120_777,
            (false, Kind::Dir) => 0x10,
            (false, _) => 0x20,
        };
        put_vint(&mut body, attr);
        let crc = crc32(entry.data) ^ u32::from(entry.bad_crc);
        body.extend_from_slice(&crc.to_le_bytes());
        body.push(0);
        body.push(u8::from(entry.unix));
        put_vint(&mut body, entry.name.len() as u64);
        body.extend_from_slice(entry.name);
        body.extend_from_slice(&extra);
        let mut header = Vec::new();
        put_vint(&mut header, body.len() as u64);
        header.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&header).to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(entry.data);
    }
    out.extend_from_slice(END);
    out
}

/// A copy of `rar.rar` with these entries in place of its own.
pub fn with_entries15(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut out = MAIN15.to_vec();
    for entry in entries {
        let data = match entry.kind {
            Kind::Redirect(_, target) => target,
            _ => entry.data,
        };
        let is_dir = matches!(entry.kind, Kind::Dir);
        let flags = 0x8000u16 | if is_dir { 0xe0 } else { 0 };
        let size = 32 + entry.name.len() as u16;
        let mut body = vec![0x74];
        body.extend_from_slice(&flags.to_le_bytes());
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.push(if entry.unix { 3 } else { 2 });
        let crc = crc32(data) ^ u32::from(entry.bad_crc);
        body.extend_from_slice(&crc.to_le_bytes());
        body.extend_from_slice(b"\xb7\x76\xda\x3e");
        body.extend_from_slice(&[29, 0x30]);
        body.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
        let attr: u32 = match (entry.unix, entry.kind) {
            (true, Kind::File) => 0o100_644,
            (true, Kind::Dir) => 0o040_755,
            (true, Kind::Redirect(..)) => 0o120_777,
            (false, Kind::Dir) => 0x10,
            (false, _) => 0x20,
        };
        body.extend_from_slice(&attr.to_le_bytes());
        body.extend_from_slice(entry.name);
        out.extend_from_slice(&(crc32(&body) as u16).to_le_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(data);
    }
    out.extend_from_slice(END15);
    out
}

fn get_vint(data: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in 0..10 {
        let byte = *data.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << (shift * 7);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Makes the CRCs of the headers right again, as far as they can be followed,
/// so that damage to a header gets past reading it.
pub fn fix_header_crcs(data: &mut [u8]) {
    if data.starts_with(b"Rar!\x1a\x07\x01\x00") {
        fix_rar5(data);
    } else if data.starts_with(b"Rar!\x1a\x07\x00") {
        fix_rar15(data);
    }
}

fn fix_rar5(data: &mut [u8]) {
    let mut at = 8;
    while at + 7 <= data.len() {
        let start = at + 4;
        let mut cursor = start;
        let Some(size) = get_vint(data, &mut cursor) else {
            return;
        };
        let Some(end) = usize::try_from(size)
            .ok()
            .and_then(|s| cursor.checked_add(s))
            .filter(|&end| end <= data.len())
        else {
            return;
        };
        let crc = crc32(&data[start..end]);
        data[at..at + 4].copy_from_slice(&crc.to_le_bytes());

        let Some(_kind) = get_vint(data, &mut cursor) else {
            return;
        };
        let Some(flags) = get_vint(data, &mut cursor) else {
            return;
        };
        if flags & 1 != 0 && get_vint(data, &mut cursor).is_none() {
            return;
        }
        let mut pack_size = 0;
        if flags & 2 != 0 {
            let Some(size) = get_vint(data, &mut cursor) else {
                return;
            };
            pack_size = size;
        }
        let Some(next) = usize::try_from(pack_size)
            .ok()
            .and_then(|s| end.checked_add(s))
        else {
            return;
        };
        at = next;
    }
}

fn fix_rar15(data: &mut [u8]) {
    let mut at = 7;
    while at + 7 <= data.len() {
        let flags = u16::from_le_bytes([data[at + 3], data[at + 4]]);
        let size = usize::from(u16::from_le_bytes([data[at + 5], data[at + 6]]));
        if size < 7 || at + size > data.len() {
            return;
        }
        let crc = crc32(&data[at + 2..at + size]) as u16;
        data[at..at + 2].copy_from_slice(&crc.to_le_bytes());
        let mut add = 0;
        if flags & 0x8000 != 0 && at + 11 <= data.len() {
            add = u32::from_le_bytes([data[at + 7], data[at + 8], data[at + 9], data[at + 10]]);
        }
        at = at.saturating_add(size).saturating_add(add as usize);
    }
}
