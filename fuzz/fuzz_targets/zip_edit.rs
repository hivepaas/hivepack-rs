//! Opens the input as a ZIP archive with hivepack::zip, makes the edits its
//! first bytes choose (the count, then a kind and an index for each),
//! adding and replacing data, changing methods and encrypting among them,
//! and writes
//! it with `close_to`, or `close_to_cloning` if the first byte's top bit is
//! set. The archive `close_to` writes must open, with the entries that are
//! not deleted, in order, as edited: their names, comments, attributes,
//! times, sizes and data, read with the passwords the edits set. A panic
//! is a bug.
//! `crates/hivepack/tests/zip_oracle.rs` compares the edits and what is written
//! with libzip through the oracle.

#![no_main]

use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};

use hivepack::zip::{
    Archive, ArchiveFlags, BufferSource, Closed, EXTRA_FIELD_ALL, EXTRA_FIELD_NEW, ErrorCode,
    Flags, OpenFlags, ReadAt, Stat, cm, em, stat,
};
use libfuzzer_sys::fuzz_target;

/// The raw data of entry `i`, as stored.
fn raw_data<R: ReadAt>(za: &Archive<R>, i: u64) -> Option<Vec<u8>> {
    let mut zf = za.fopen_index(i, Flags::ENCRYPTED).ok()?;
    let mut data = Vec::new();
    zf.read_to_end(&mut data).ok()?;
    Some(data)
}

/// The data of entry `i`, decompressed, if it reads.
fn entry_data<R: ReadAt>(za: &Archive<R>, i: u64) -> Option<Vec<u8>> {
    let mut zf = za.fopen_index(i, Flags::NONE).ok()?;
    let mut data = Vec::new();
    zf.read_to_end(&mut data).ok()?;
    Some(data)
}

/// The passwords the edits encrypt with.
const PASSWORDS: [&[u8]; 3] = [b"foo", b"bar", b""];

/// Whether entry `i` reads as `data`, without a password or with one of
/// the edits'.
fn reads_as<R: ReadAt>(za: &Archive<R>, i: u64, data: &[u8]) -> bool {
    std::iter::once(None)
        .chain(PASSWORDS.iter().map(|p| Some(*p)))
        .any(|password| {
            let Ok(mut zf) = za.fopen_index_encrypted(i, Flags::NONE, password) else {
                return false;
            };
            let mut read = Vec::new();
            zf.read_to_end(&mut read).is_ok() && read == data
        })
}

/// What the API says of an entry before the archive is written.
struct EntryState {
    index: u64,
    name: Vec<u8>,
    comment: Vec<u8>,
    attributes: (u8, u32),
    /// as stored; new data only has it once written, from its source
    dos_time: Option<(u16, u16)>,
    stat: Stat<'static>,
    data: Option<Vec<u8>>,
    raw: Option<Vec<u8>>,
}

/// The entries with names, which are those written, and the archive
/// comment.
fn archive_state<R: ReadAt>(za: &Archive<R>) -> (Vec<EntryState>, Vec<u8>) {
    let entries = (0..za.get_num_entries(Flags::NONE))
        .filter_map(|i| {
            Some(EntryState {
                index: i,
                name: za.get_name(i, Flags::ENC_RAW).ok()?.to_vec(),
                comment: za.file_get_comment(i, Flags::ENC_RAW).ok()?.to_vec(),
                attributes: za.file_get_external_attributes(i, Flags::NONE).ok()?,
                // An entry with new data cannot be read raw.
                dos_time: match za.fopen_index(i, Flags::COMPRESSED) {
                    Err(e) if e.code() == ErrorCode::Changed => None,
                    _ => Some(za.file_get_dos_time(i, Flags::NONE).ok()?),
                },
                stat: Stat {
                    name: None,
                    ..za.stat_index(i, Flags::NONE).ok()?
                },
                data: entry_data(za, i),
                raw: raw_data(za, i),
            })
        })
        .collect();
    (entries, za.get_archive_comment(Flags::ENC_RAW).to_vec())
}

/// That `written` has the entries of `expected`, in order, as they were
/// edited. What libzip writes from an edited archive is not always what
/// its API said before (see `check_written` in `crates/hivepack/tests/zip_oracle.rs`,
/// which this follows).
/// Whether an MS-DOS time and date name a moment as they are, which the
/// conversions to and from a `time_t` leave as it was.
fn dos_time_in_range(time: u16, date: u16) -> bool {
    let (seconds, minutes, hours) = (time & 0x1f, (time >> 5) & 0x3f, time >> 11);
    let (day, month, year) = (date & 0x1f, (date >> 5) & 0xf, 1980 + (date >> 9));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    seconds < 30 && minutes < 60 && hours < 24 && (1..=12).contains(&month) && (1..=days).contains(&day)
}

fn check_written(
    expected: &(Vec<EntryState>, Vec<u8>),
    encrypted: &[u64],
    unreadable: &[u64],
    written: &[u8],
) {
    let (entries, archive_comment) = expected;
    // Something that looks like an end of central directory record, or a
    // Zip64 one or its locator, in a name, a comment, an extra field or the
    // data may be taken for the real one: libzip does not check that what
    // it writes reads back.
    let count = |signature: &[u8]| written.windows(4).filter(|&w| w == signature).count();
    let (eocd64, locator) = (count(b"PK\x06\x06"), count(b"PK\x06\x07"));
    if count(b"PK\x05\x06") > 1 || eocd64 > 1 || locator != eocd64 {
        return;
    }
    let new = match Archive::open(written, OpenFlags(0)) {
        Ok(new) => new,
        Err(e) => panic!("the written archive does not open: {e} ({:?})", e.detail()),
    };
    // An entry deleted, then given changes, has its name again, though it
    // is not written.
    if new.get_num_entries(Flags::NONE) != entries.len() as u64 {
        return;
    }
    for (j, e) in entries.iter().enumerate() {
        let j = j as u64;
        // An entry encrypted anew is read through the layers that decrypt
        // and decompress it, so it has the time of its stat, and the layer
        // that encrypts stops at the first short read, so its CRC is never
        // checked: it takes the CRC and length of its data.
        let reencrypted = encrypted.contains(&e.index)
            || (e.stat.valid & stat::COMP_SIZE == 0 && e.stat.encryption_method != em::NONE);
        assert_eq!(new.get_name(j, Flags::ENC_RAW).ok(), Some(&e.name[..]));
        assert_eq!(
            new.file_get_comment(j, Flags::ENC_RAW).ok(),
            Some(&e.comment[..])
        );
        assert_eq!(
            new.file_get_external_attributes(j, Flags::NONE).ok(),
            Some(e.attributes)
        );
        let Ok(a) = new.stat_index(j, Flags::NONE) else {
            panic!("stat of entry {j}");
        };
        let b = e.stat;
        // An entry compressed again has no compressed size until it is,
        // and is stored differently, with the time of its stat and the
        // length it decompresses to.
        let recompressed = b.valid & stat::COMP_SIZE == 0;
        if let Some(dos_time) = e.dos_time
            && !recompressed
            && !reencrypted
        {
            assert_eq!(new.file_get_dos_time(j, Flags::NONE).ok(), Some(dos_time));
        }
        let mut both = a.valid & b.valid;
        if e.dos_time.is_none() {
            both &= stat::SIZE | stat::CRC;
        }
        if recompressed {
            both &= stat::CRC;
        }
        if reencrypted {
            both &= stat::ENCRYPTION_METHOD;
            // An entry whose flags have the strong encryption bit keeps it
            // when encrypted, as in libzip, and reads back as encrypted
            // with an unknown method.
            if a.encryption_method == em::UNKNOWN {
                both = 0;
            }
        }
        for (field, x, y) in [
            (stat::SIZE, a.size, b.size),
            (stat::COMP_SIZE, a.comp_size, b.comp_size),
            (
                stat::COMP_METHOD,
                u64::from(a.comp_method),
                u64::from(b.comp_method),
            ),
            (
                stat::ENCRYPTION_METHOD,
                u64::from(a.encryption_method),
                u64::from(b.encryption_method),
            ),
            (stat::CRC, u64::from(a.crc), u64::from(b.crc)),
        ] {
            if both & field != 0 {
                assert_eq!(x, y, "stat field {field:#x} of entry {j}");
            }
        }
        // Before it is written, new data is read with the method the entry
        // had, as libzip reads it.
        // ZipCrypto encrypts with an empty password, but reading takes an
        // empty password for none, as libzip does: such an entry cannot be
        // read. Nor can one compressed again and encrypted with ZipCrypto
        // from an MS-DOS time out of range: the header keeps the time,
        // but the check byte comes from the time of its stat, back in
        // range, as in libzip.
        let check_byte_moved = recompressed
            && a.encryption_method == em::TRAD_PKWARE
            && e.dos_time.is_some_and(|(time, date)| !dos_time_in_range(time, date));
        // A WinZip AES entry of AE-2 written as AE-1 (see below) has its CRC
        // checked now, which AE-2 left as it was. And one encrypted with an
        // unknown method (see above) is decrypted by nothing.
        let crc_checked_now = a.valid & stat::CRC != 0 && b.valid & stat::CRC == 0;
        if let Some(data) = &e.data
            && e.dos_time.is_some()
            && !unreadable.contains(&e.index)
            && !check_byte_moved
            && !crc_checked_now
            && a.encryption_method != em::UNKNOWN
        {
            assert!(reads_as(&new, j, data), "data of entry {j}");
        }
        // A WinZip AES entry of AE-2, without a CRC, is written as AE-1 if
        // it has 20 bytes or more, and its CRC is then checked on reading,
        // on the encrypted data.
        if let Some(raw) = &e.raw
            && a.valid & stat::CRC == b.valid & stat::CRC
            && !recompressed
            && !reencrypted
        {
            assert_eq!(
                raw_data(&new, j).as_ref(),
                Some(raw),
                "raw data of entry {j}"
            );
        }
    }
    // As in libzip, a comment removed is still given until the archive is
    // written.
    let comment = new.get_archive_comment(Flags::ENC_RAW);
    assert!(comment.is_empty() || comment == &archive_comment[..]);
}

/// New data the op bytes pick: runs, text and bytes that do not compress,
/// some longer than libzip reads at a time.
fn new_data(kind: u8, arg: u8) -> BufferSource {
    let len = usize::from(arg) * [1, 37, 300][usize::from(kind >> 6) % 3];
    let data: Vec<u8> = match kind & 0x30 {
        0x00 => vec![arg; len],
        0x10 => (0..len).map(|i| b"hivepack zip "[i % 13]).collect(),
        _ => (0..len)
            .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8 ^ arg)
            .collect(),
    };
    BufferSource::with_mtime(data, 1_000_000_000 + i64::from(arg) * 86_400)
}

fuzz_target!(|data: &[u8]| {
    let Some((&count_byte, rest)) = data.split_first() else {
        return;
    };
    let count = usize::from(count_byte % 8);
    if rest.len() < 2 * count {
        return;
    }
    let (ops, zip) = rest.split_at(2 * count);
    let Ok(mut za) = Archive::open(zip, OpenFlags(0)) else {
        return;
    };
    let n = za.get_num_entries(Flags::NONE);
    let (mut encrypted, mut unreadable) = (Vec::new(), Vec::new());
    for op in ops.chunks(2) {
        let (kind, arg) = (op[0], op[1]);
        let i = u64::from(arg) % (n + 1);
        // ZIP_FL_LOCAL, ZIP_FL_CENTRAL or both, or neither.
        let ef_flags = Flags(u32::from(kind & 0x30) << 4);
        let _ = match kind % 17 {
            0 => za.delete(i),
            1 => za.file_rename(
                i,
                &[b'r', arg, b'/'][..1 + usize::from(arg % 3)],
                Flags::NONE,
            ),
            2 => za.file_set_comment(i, op, Flags(u32::from(kind & 0x80) << 4)),
            3 => za.set_archive_comment(&op[..usize::from(arg % 3)]),
            4 => za.file_set_dostime(
                i,
                u16::from(arg) << 8,
                0x21 | u16::from(kind) << 9,
                Flags::NONE,
            ),
            5 => za.file_set_mtime(i, i64::from(arg) << (kind % 64), Flags::NONE),
            6 => za.file_set_external_attributes(i, Flags::NONE, arg % 20, u32::from(kind) << 16),
            7 => za.unchange(i),
            8 => {
                za.unchange_all();
                Ok(())
            }
            9 => za.set_archive_flag(
                ArchiveFlags::CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE,
                kind & 0x80 != 0,
            ),
            10 => za.file_extra_field_set(
                i,
                0xcafe,
                if kind & 0x40 != 0 { EXTRA_FIELD_NEW } else { 0 },
                &op[..usize::from(arg % 3)],
                ef_flags,
            ),
            11 => za.file_extra_field_delete(
                i,
                if kind & 0x40 != 0 {
                    EXTRA_FIELD_ALL
                } else {
                    u16::from(arg % 3)
                },
                ef_flags,
            ),
            12 => za
                .file_add(
                    &[b'n', arg],
                    new_data(kind, arg),
                    Flags(u32::from(kind & 0x40) << 7),
                )
                .map(|_| ()),
            13 => za.file_replace(i, new_data(kind, arg), Flags::NONE),
            14 => {
                encrypted.push(i);
                let method = [em::NONE, em::TRAD_PKWARE, em::AES_128, em::AES_192, em::AES_256]
                    [usize::from(arg % 5)];
                let password = [None, Some(PASSWORDS[0]), Some(PASSWORDS[1]), Some(PASSWORDS[2])]
                    [usize::from(kind >> 6)];
                if password == Some(b"") {
                    unreadable.push(i);
                }
                za.file_set_encryption(i, method, password)
            }
            15 => {
                za.set_default_password([None, Some(PASSWORDS[0])][usize::from(kind >> 7)]);
                Ok(())
            }
            _ => za.set_file_compression(
                i,
                [
                    i32::from(cm::STORE),
                    i32::from(cm::DEFLATE),
                    cm::DEFAULT,
                    i32::from(cm::BZIP2),
                    i32::from(cm::LZMA),
                    i32::from(cm::XZ),
                    i32::from(cm::ZSTD),
                ]
                    [usize::from(arg % 7)],
                u32::from(kind >> 4),
            ),
        };
    }
    let mut out = Cursor::new(Vec::new());
    let expected = archive_state(&za);
    // Random bytes the same on every run.
    let state = Mutex::new(0u8);
    za.set_random_source(Some(Arc::new(move |buffer: &mut [u8]| {
        let mut x = state.lock().map_err(|_| std::io::ErrorKind::Other)?;
        for byte in buffer {
            *x = x.wrapping_mul(5).wrapping_add(1);
            *byte = *x;
        }
        Ok(())
    })));
    if count_byte & 0x80 != 0 {
        // Cloning what is kept: an entry before the first one that changed
        // is cut there if its data reaches past it, as in libzip, so only
        // that it does not panic.
        let _ = za.close_to_cloning(&mut out, |offset| offset % 2 == 0);
    } else if matches!(za.close_to(&mut out), Ok(Closed::Written))
        && !za.get_archive_flag(ArchiveFlags::WANT_TORRENTZIP, Flags::NONE)
    {
        check_written(&expected, &encrypted, &unreadable, out.get_ref());
    }
});
