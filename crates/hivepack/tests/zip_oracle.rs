//! Comparison with libzip 1.12.1 through `tools/zip-oracle`: opening
//! archives, and everything the central directory and local headers say
//! about their entries.
//!
//! The oracle is a small C program built with libzip's sources by
//! `scripts/testdata.py`. It answers requests such as `open 4 b 504b0506...`
//! (open with `ZIP_CHECKCONS` from a buffer) by calling libzip, one line per
//! request: the error, or the entries' names, stat, attributes, comments,
//! extra fields, data offsets and name lookups. [`answer`] answers the same
//! requests with the port, so the two can be compared as text.
//!
//! - With the oracle built, libzip's own test archives (`regress/`) and
//!   generated ones are compared with libzip directly. The generated ones
//!   come from [`archive`], which writes every kind of header field libzip
//!   reads, right and wrong, and some are then damaged.
//! - Everywhere, `testdata/oracle/zip-open.txt` replays answers libzip gave
//!   earlier. `cargo test -p hivepack --all-features --test zip_oracle
//!   record_open_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "zip_support/mod.rs"]
mod support;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use hivepack::deflate::{
    Deflate, Flush as DeflateFlush, InBuffer, OutBuffer, Status as DeflateStatus, crc32,
};
use hivepack::zip::{
    Archive, ArchiveFlags, BufferSource, Closed, DataSource, Detail, Error, ErrorCode, Flags,
    OpenFlags, RandomSource, ReadAt,
};
use support::{Oracle, Rng, damage, hex, recorded_form, repository, unhex};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/zip-open.txt")
}

fn recorded_read_path() -> PathBuf {
    repository().join("testdata/oracle/zip-read.txt")
}

fn recorded_encrypt_path() -> PathBuf {
    repository().join("testdata/oracle/zip-encrypt.txt")
}

fn recorded_decrypt_path() -> PathBuf {
    repository().join("testdata/oracle/zip-decrypt.txt")
}

fn recorded_range_path() -> PathBuf {
    repository().join("testdata/oracle/zip-range.txt")
}

fn recorded_edit_path() -> PathBuf {
    repository().join("testdata/oracle/zip-edit.txt")
}

fn error_text(e: Error) -> String {
    format!("e{}/{}", e.code().number(), e.system())
}

/// A name as C sees it: up to its first NUL byte.
fn c_string(name: &[u8]) -> &[u8] {
    &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())]
}

/// The oracle's description of an open archive, or of the error.
fn describe<R: ReadAt>(result: hivepack::zip::Result<Archive<R>>) -> String {
    let za = match result {
        Ok(za) => za,
        Err(e) => return error_text(e),
    };
    let n = za.get_num_entries(Flags::NONE);
    let mut text = format!(
        "ok {n} {} {} {}",
        u8::from(za.get_archive_flag(ArchiveFlags::IS_TORRENTZIP, Flags::NONE)),
        hex(za.get_archive_comment(Flags::NONE)),
        hex(za.get_archive_comment(Flags::ENC_RAW))
    );
    for i in 0..n {
        let name = |za: &Archive<R>, flags| match za.get_name(i, flags) {
            Ok(name) => hex(c_string(name)),
            Err(e) => error_text(e),
        };
        let _ = write!(
            text,
            " |{} {} {} ",
            name(&za, Flags::NONE),
            name(&za, Flags::ENC_RAW),
            name(&za, Flags::ENC_STRICT)
        );
        match za.stat_index(i, Flags::NONE) {
            Ok(st) => {
                let _ = write!(
                    text,
                    "{}/{}/{}/{}/{}/{}/{}",
                    st.valid,
                    st.size,
                    st.comp_size,
                    st.mtime,
                    st.crc,
                    st.comp_method,
                    st.encryption_method
                );
            }
            Err(e) => text.push_str(&error_text(e)),
        }
        match za.file_get_external_attributes(i, Flags::NONE) {
            Ok((opsys, attributes)) => {
                let _ = write!(text, " {opsys}/{attributes}");
            }
            Err(e) => text.push_str(&format!(" {}", error_text(e))),
        }
        for flags in [Flags::NONE, Flags::ENC_RAW] {
            match za.file_get_comment(i, flags) {
                Ok(comment) => text.push_str(&format!(" {}", hex(comment))),
                Err(e) => text.push_str(&format!(" {}", error_text(e))),
            }
        }
        for (tag, flags) in [("c", Flags::CENTRAL), ("l", Flags::LOCAL)] {
            text.push_str(&format!(" {tag}{}", extra_fields(&za, i, flags)));
        }
        match za.file_get_offset(i) {
            Ok(offset) => text.push_str(&format!(" o{offset}")),
            Err(e) => text.push_str(&format!(" o{}", error_text(e))),
        }
        text.push_str(" n");
        match za.get_name(i, Flags::NONE) {
            Ok(name) => {
                let name = c_string(name).to_vec();
                let last = match name.iter().rposition(|&b| b == b'/') {
                    Some(p) => name[p + 1..].to_vec(),
                    None => name.clone(),
                };
                let raw = c_string(za.get_name(i, Flags::ENC_RAW).unwrap()).to_vec();
                let lookups = [
                    (&name, Flags::NONE),
                    (&name, Flags::NOCASE),
                    (&last, Flags::NODIR),
                    (&raw, Flags::ENC_RAW),
                ];
                let found: Vec<String> = lookups
                    .iter()
                    .map(|(fname, flags)| match za.name_locate(fname, *flags) {
                        Ok(index) => index.to_string(),
                        Err(e) => error_text(e),
                    })
                    .collect();
                text.push_str(&found.join(","));
            }
            Err(_) => text.push('-'),
        }
    }
    text
}

/// The oracle's `put_extra_fields`: the count and each field of entry `i`
/// as `flags` ask, or the error.
fn extra_fields<R: ReadAt>(za: &Archive<R>, i: u64, flags: Flags) -> String {
    let count = match za.file_extra_fields_count(i, flags) {
        Ok(count) => count,
        Err(e) => return error_text(e),
    };
    let fields: Vec<String> = (0..count)
        .map(|j| match za.file_extra_field_get(i, j as u16, flags) {
            Ok((id, data)) => format!("{id}={}", hex(data)),
            Err(e) => error_text(e),
        })
        .collect();
    format!("{count}:{}", fields.join(","))
}

fn fnv(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// The oracle's answer to a `read` request: every entry read in pieces of
/// `chunks`, up to `limit` bytes, then closed.
fn read_entries<R: ReadAt>(
    result: hivepack::zip::Result<Archive<R>>,
    how: &str,
    password: &[u8],
    fflags: u32,
    chunks: &str,
    limit: i64,
) -> String {
    let mut za = match result {
        Ok(za) => za,
        Err(e) => return error_text(e),
    };
    if how == "d" || how == "x" {
        za.set_default_password(Some(password));
    }
    let chunks: Vec<i64> = chunks.split(',').map(|c| c.parse().unwrap()).collect();
    let n = za.get_num_entries(Flags::NONE);
    let mut text = format!("ok {n}");
    let mut buffer = vec![0u8; 1 << 20];
    for i in 0..n {
        text.push_str(" |");
        // libzip has no Deflate64 nor PPMd: where the port decodes them,
        // libzip refuses to open the entry, once it has checked the password
        // and sizes and before it reads the local header. tests/deflate64.rs
        // and tests/ppmd.rs check what the port reads.
        let raw = Flags(fflags).intersects(Flags::COMPRESSED | Flags::ENCRYPTED);
        let st = za.stat_index(i, Flags::NONE).ok();
        let unread = !raw && st.as_ref().is_some_and(|st| libzip_lacks(st.comp_method));
        let opened = match how {
            "e" => za.fopen_index_encrypted(i, Flags(fflags), Some(password)),
            "x" => za.fopen_index_encrypted(i, Flags(fflags), Some(b"")),
            _ => za.fopen_index(i, Flags(fflags)),
        };
        let mut zf = match opened {
            Ok(zf) => zf,
            Err(e) if unread && past_libzip_refusal(&e, st.as_ref(), 0, None) => {
                text.push_str("e16/0");
                continue;
            }
            Err(e) => {
                text.push_str(&error_text(e));
                continue;
            }
        };
        let (mut data_hash, mut returns_hash) = (0xcbf2_9ce4_8422_2325, 0xcbf2_9ce4_8422_2325);
        let (mut total, mut reads, mut next) = (0i64, 0, 0);
        let mut end = "eof".to_string();
        loop {
            let mut want = chunks[next];
            next = (next + 1) % chunks.len();
            if limit >= 0 && want > limit - total {
                want = limit - total;
            }
            if limit >= 0 && want == 0 {
                end = "limit".into();
                break;
            }
            reads += 1;
            match zf.fread(&mut buffer[..want as usize]) {
                Err(e) => {
                    returns_hash = fnv(returns_hash, b"-1,");
                    end = error_text(e);
                    break;
                }
                Ok(got) => {
                    returns_hash = fnv(returns_hash, format!("{got},").as_bytes());
                    if got == 0 {
                        break;
                    }
                    data_hash = fnv(data_hash, &buffer[..got]);
                    total += got as i64;
                }
            }
        }
        let close = match zf.fclose() {
            Ok(()) => 0,
            Err(e) => e.code().number(),
        };
        if unread {
            text.push_str("e16/0");
            continue;
        }
        let _ = write!(
            text,
            "{total}/{data_hash:016x}/{reads}/{returns_hash:016x}/{end}/{close}"
        );
    }
    text
}

/// The oracle's answer to a `range` request: part of every entry read, as
/// ziptool's cat_partial reads it.
fn range_entries<R: ReadAt>(
    result: hivepack::zip::Result<Archive<R>>,
    start: u64,
    len: i64,
) -> String {
    let za = match result {
        Ok(za) => za,
        Err(e) => return error_text(e),
    };
    let n = za.get_num_entries(Flags::NONE);
    let mut text = format!("ok {n}");
    let mut buffer = vec![0u8; 8192];
    let len = u64::try_from(len).ok();
    for i in 0..n {
        text.push_str(" |");
        let st = za.stat_index(i, Flags::NONE).ok();
        let unread = st.as_ref().is_some_and(|st| libzip_lacks(st.comp_method));
        // zip_source_zip_file_create sets ZIP_ER_COMPNOTSUPP on the archive's
        // error, not on the one it is given, which stays ZIP_ER_OK; the port
        // returns the error. libzip has no Deflate64 nor PPMd (see
        // read_entries).
        let mut zf = match za.fopen_index_range(i, Flags::NONE, start, len) {
            Err(e) if e.code() == ErrorCode::CompNotSupp => {
                text.push_str("e0/0");
                continue;
            }
            Err(e) if unread && past_libzip_refusal(&e, st.as_ref(), start, len) => {
                text.push_str("e0/0");
                continue;
            }
            Ok(_) if unread => {
                text.push_str("e0/0");
                continue;
            }
            Ok(zf) => zf,
            Err(e) => {
                text.push_str(&error_text(e));
                continue;
            }
        };
        let (mut hash, mut total) = (0xcbf2_9ce4_8422_2325, 0u64);
        let end = loop {
            match zf.fread(&mut buffer) {
                Ok(0) => break None,
                Ok(got) => {
                    hash = fnv(hash, &buffer[..got]);
                    total += got as u64;
                }
                Err(e) => break Some(e),
            }
        };
        let _ = write!(text, "{total}/{hash:016x}/");
        match end {
            Some(e) => {
                text.push_str(&error_text(e));
                text.push_str("/-");
            }
            None => match zf.fclose() {
                Ok(()) => text.push_str("eof/0"),
                Err(e) => text.push_str(&format!("eof/{}", error_text(e))),
            },
        }
    }
    text
}

/// The port's answer to a request, in the oracle's format.
fn respond<R: ReadAt>(words: &[&str], result: hivepack::zip::Result<Archive<R>>) -> String {
    match words[0] {
        "open" => describe(result),
        "range" => range_entries(result, words[3].parse().unwrap(), words[4].parse().unwrap()),
        "decrypt" => read_entries(
            result,
            words[3],
            &unhex(words[4]),
            words[5].parse().unwrap(),
            words[6],
            words[7].parse().unwrap(),
        ),
        _ => read_entries(
            result,
            "n",
            b"",
            words[3].parse().unwrap(),
            words[4],
            words[5].parse().unwrap(),
        ),
    }
}

/// The port's answer to an `edit` request, but for closing: the edits
/// made, and what the API then says.
fn edit_ops_and_state<R: ReadAt>(za: &mut Archive<R>, ops: &str) -> String {
    let mut text = String::from("ok");
    for op in ops.split(',').filter(|&op| op != "-") {
        let fields: Vec<&str> = op[1..].splitn(5, ':').collect();
        let index = || fields[0].parse::<u64>().unwrap();
        let number = |k: usize| fields[k].parse::<i64>().unwrap();
        let flags = |k: usize| Flags(fields[k].parse().unwrap());
        let result: hivepack::zip::Result<u64> = match op.as_bytes()[0] {
            b'+' => za.file_add(
                &unhex(fields[0]),
                memory_source(fields[2], fields[3], fields[4]),
                flags(1),
            ),
            b'R' => za
                .file_replace(
                    index(),
                    memory_source(fields[1], fields[2], fields[3]),
                    Flags::NONE,
                )
                .map(|()| 0),
            b'N' => za.dir_add(&unhex(fields[0]), flags(1)).and_then(|idx| {
                za.file_set_dostime(idx, number(2) as u16, number(3) as u16, Flags::NONE)
                    .map(|()| idx)
            }),
            b'z' => za
                .set_file_compression(index(), number(1) as i32, number(2) as u32)
                .map(|()| 0),
            _ => edit_op(za, op, &fields).map(|()| 0),
        };
        match result {
            Ok(n) => text.push_str(&format!(" {n}")),
            Err(e) => text.push_str(&format!(" {}", error_text(e))),
        }
    }
    edit_state(za, text)
}

/// An op of an edit request that answers 0.
fn edit_op<R: ReadAt>(za: &mut Archive<R>, op: &str, fields: &[&str]) -> hivepack::zip::Result<()> {
    let index = || fields[0].parse::<u64>().unwrap();
    let number = |k: usize| fields[k].parse::<i64>().unwrap();
    let flags = |k: usize| Flags(fields[k].parse().unwrap());
    match op.as_bytes()[0] {
        b'd' => za.delete(index()),
        b'r' => za.file_rename(index(), &unhex(fields[1]), flags(2)),
        b'c' => za.file_set_comment(index(), &unhex(fields[1]), flags(2)),
        b'a' => za.set_archive_comment(&unhex(fields[0])),
        b't' => za.file_set_dostime(index(), number(1) as u16, number(2) as u16, Flags::NONE),
        b'm' => za.file_set_mtime(index(), number(1), Flags::NONE),
        b'x' => {
            za.file_set_external_attributes(index(), Flags::NONE, number(1) as u8, number(2) as u32)
        }
        b'u' => za.unchange(index()),
        b'U' => {
            za.unchange_all();
            Ok(())
        }
        b'A' => {
            za.unchange_archive();
            Ok(())
        }
        b'f' => za.set_archive_flag(ArchiveFlags(fields[0].parse().unwrap()), fields[1] != "0"),
        b'e' => za.file_extra_field_set(
            index(),
            number(1) as u16,
            number(2) as u16,
            &unhex(fields[3]),
            flags(4),
        ),
        b'E' => {
            za.file_extra_field_delete_by_id(index(), number(1) as u16, number(2) as u16, flags(3))
        }
        b'D' => za.file_extra_field_delete(index(), number(1) as u16, flags(2)),
        b'y' => za.file_set_encryption(
            index(),
            number(1) as u16,
            password_field(fields[2]).as_deref(),
        ),
        b'P' => {
            za.set_default_password(password_field(fields[0]).as_deref());
            Ok(())
        }
        _ => panic!("unknown op {op}"),
    }
}

/// A password of an op: none for "-", else its bytes.
fn password_field(field: &str) -> Option<Vec<u8>> {
    (field != "-").then(|| unhex(field))
}

/// The random bytes the oracle gives libzip for an edit request with
/// `ops`: the stream of `x = x * 6364136223846793005 + 1442695040888963407`
/// from the FNV-1a hash of the ops, a byte the top of each `x`.
fn oracle_random(ops: &str) -> RandomSource {
    let state = std::sync::Mutex::new(fnv(0xcbf2_9ce4_8422_2325, ops.as_bytes()));
    std::sync::Arc::new(move |buffer: &mut [u8]| {
        let mut x = state.lock().unwrap();
        for byte in buffer {
            *x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (*x >> 56) as u8;
        }
        Ok(())
    })
}

/// The passwords the ops of an edit set, and the entries whose encryption
/// they set, which are written encrypted anew.
fn encryption_ops(ops: &str) -> (Vec<Vec<u8>>, Vec<u64>) {
    let (mut passwords, mut indices) = (Vec::new(), Vec::new());
    for op in ops.split(',') {
        let fields: Vec<&str> = op.get(1..).unwrap_or_default().split(':').collect();
        match op.as_bytes().first() {
            Some(b'y') => {
                indices.push(fields[0].parse().unwrap());
                passwords.extend(password_field(fields[2]));
            }
            Some(b'P') => passwords.extend(password_field(fields[0])),
            _ => {}
        }
    }
    (passwords, indices)
}

/// The oracle's source of data in memory with a time: its size known
/// (`s`), as a buffer source has it, or not (`u`).
fn memory_source(mtime: &str, data: &str, kind: &str) -> MemorySource {
    MemorySource {
        data: unhex(data),
        mtime: mtime.parse().unwrap(),
        known_size: kind != "u",
    }
}

struct MemorySource {
    data: Vec<u8>,
    mtime: i64,
    known_size: bool,
}

impl DataSource for MemorySource {
    fn stat(&self) -> hivepack::zip::Result<hivepack::zip::Stat<'static>> {
        use hivepack::zip::stat;
        let mut st = BufferSource::with_mtime(self.data.clone(), self.mtime).stat()?;
        if !self.known_size {
            st.valid = stat::MTIME;
        }
        Ok(st)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> hivepack::zip::Result<usize> {
        let start = (offset as usize).min(self.data.len());
        let n = buf.len().min(self.data.len() - start);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }
}

/// What the oracle answers after the edits: the archive comment, and for
/// each entry what the API says of it.
fn edit_state<R: ReadAt>(za: &Archive<R>, mut text: String) -> String {
    let _ = write!(
        text,
        " |{} {}",
        hex(za.get_archive_comment(Flags::NONE)),
        hex(za.get_archive_comment(Flags::UNCHANGED))
    );
    for i in 0..za.get_num_entries(Flags::NONE) {
        let name = |za: &Archive<R>, flags| match za.get_name(i, flags) {
            Ok(name) => hex(c_string(name)),
            Err(e) => error_text(e),
        };
        let comment = match za.file_get_comment(i, Flags::NONE) {
            Ok(comment) => hex(comment),
            Err(e) => error_text(e),
        };
        let attributes = match za.file_get_external_attributes(i, Flags::NONE) {
            Ok((opsys, attributes)) => format!("{opsys}:{attributes}"),
            Err(e) => error_text(e),
        };
        let mtime = match za.stat_index(i, Flags::NONE) {
            Ok(st) => st.mtime.to_string(),
            Err(e) => error_text(e),
        };
        let found = match za.get_name(i, Flags::NONE) {
            Ok(name) => match za.name_locate(c_string(name), Flags::NONE) {
                Ok(index) => index.to_string(),
                Err(e) => error_text(e),
            },
            Err(e) => error_text(e),
        };
        let _ = write!(
            text,
            " |{}/{}/{comment}/{attributes}/{mtime}/{found}/c{}/l{}",
            name(za, Flags::NONE),
            name(za, Flags::UNCHANGED),
            extra_fields(za, i, Flags::CENTRAL),
            extra_fields(za, i, Flags::LOCAL)
        );
    }

    text
}

/// [`edit_ops_and_state`], then the archive written as the oracle's file
/// source has it written.
fn edit_archive<R: ReadAt>(za: &mut Archive<R>, ops: &str) -> String {
    let mut text = edit_ops_and_state(za, ops);
    text.push_str(" |");
    let mut out = std::io::Cursor::new(Vec::new());
    let expected = archive_state(za, ops);
    za.set_random_source(Some(oracle_random(ops)));
    match za.close_to(&mut out) {
        Ok(Closed::Unchanged) => text.push_str("unchanged"),
        Ok(Closed::Removed) => text.push_str("removed"),
        Ok(Closed::Written) => {
            if !za.get_archive_flag(ArchiveFlags::WANT_TORRENTZIP, Flags::NONE) {
                check_written(&expected, out.get_ref());
            }
            let _ = write!(text, "written {}", hex(out.get_ref()));
        }
        Err(e) => text.push_str(&error_text(e)),
    }
    text
}

/// Whether the archive libzip wrote, in its answer to an edit request,
/// does not read back for want of a value in a Zip64 extra field: libzip
/// writes a size or offset of exactly 0xffffffff, or a disk number of
/// 0xffff or more, without one, where the port writes it.
fn writes_invalid_zip64(want: &str) -> bool {
    written_part(want).is_some_and(|(_, written)| {
        Archive::open(unhex(written).as_slice(), OpenFlags(0))
            .err()
            .and_then(|e| e.detail())
            .is_some_and(|(detail, _)| detail == Detail::InvalidZip64Ef)
    })
}

/// Whether the port's error opening an entry of a method libzip lacks
/// comes from past the
/// point where libzip refuses the method: not the password, nor the sizes
/// of the entry and the part asked for, which it checks first (with no
/// compressed data, the window on the empty buffer has no room for a size).
/// The same ZIP_ER_INVAL comes from a seek to a local header past the end of
/// the archive, which libzip does not reach.
fn past_libzip_refusal(
    e: &hivepack::zip::Error,
    st: Option<&hivepack::zip::Stat<'_>>,
    start: u64,
    len: Option<u64>,
) -> bool {
    match (e.code(), st) {
        (ErrorCode::NoPasswd, _) => false,
        (ErrorCode::Inval, Some(st)) => {
            start.saturating_add(len.unwrap_or(0)) <= st.size
                && (len.is_some() || st.size - start <= i64::MAX as u64)
                && st.comp_size <= i64::MAX as u64
                && (st.comp_size != 0 || len.unwrap_or(st.size - start) == 0)
        }
        (ErrorCode::Inval, None) => false,
        _ => true,
    }
}

/// Whether the port reads `method` where libzip refuses it as
/// `ZIP_ER_COMPNOTSUPP`: Deflate64 and PPMd.
fn libzip_lacks(method: u16) -> bool {
    method == hivepack::zip::cm::DEFLATE64 || method == hivepack::zip::cm::PPMD
}

/// Whether the archive of a request has an entry of a method libzip lacks.
fn has_method_libzip_lacks(request: &str) -> bool {
    let data = unhex(request.rsplit(' ').next().unwrap_or("-"));
    Archive::open(data.as_slice(), OpenFlags(0)).is_ok_and(|za| {
        (0..za.get_num_entries(Flags::NONE)).any(|i| {
            za.stat_index(i, Flags::NONE)
                .is_ok_and(|st| libzip_lacks(st.comp_method))
        })
    })
}

/// An edit answer before the archive written, and the archive, from a
/// file (`written`) or a buffer (`buffer`).
fn written_part(answer: &str) -> Option<(&str, &str)> {
    let (head, tail) = answer.rsplit_once(" |")?;
    let written = tail
        .strip_prefix("written ")
        .or_else(|| tail.strip_prefix("buffer "))?;
    Some((head, written))
}

/// Checks the port's answer to an edit request against libzip's: the same,
/// but for the archive written where libzip's does not read back (see
/// [`writes_invalid_zip64`]); the port's is checked by [`check_written`].
fn assert_edit(request: &str, want: &str, context: &str) {
    let got = checked_answer(request, want);
    // libzip has no Deflate64 nor PPMd: where it refuses to recompress such
    // an entry, the port recompresses it, or fails on its data.
    if got != want && want.ends_with(" |e16/0") && has_method_libzip_lacks(request) {
        let head = |answer: &str| answer.rsplit_once(" |").map(|(head, _)| head.to_string());
        assert_eq!(head(&got), head(want), "{context}");
        return;
    }
    if got != want && writes_invalid_zip64(want) {
        let head = |answer: &str| written_part(answer).map(|(head, _)| head.to_string());
        assert_eq!(head(&got), head(want), "{context}");
        return;
    }
    assert_eq!(got, want, "{context}");
}

/// Whether libzip's buffer source of `len` bytes, in fragments of
/// `fragment_size` (one if 0), can clone its first `offset` bytes, as
/// `buffer_clone` decides: not past its end, nor where more of the
/// fragment it ends in would be left over than it keeps.
fn buffer_can_clone(len: u64, fragment_size: u64, offset: u64) -> bool {
    if offset == 0 {
        return true;
    }
    if offset > len {
        return false;
    }
    let fragment_size = if fragment_size == 0 {
        len
    } else {
        fragment_size
    };
    let nfragments = len.div_ceil(fragment_size);
    let length = |i: u64| fragment_size.min(len - i * fragment_size);
    let mut fragment = (offset / fragment_size).min(nfragments - 1);
    let mut fragment_offset = offset - fragment * fragment_size;
    if fragment_offset == 0 {
        // We can't be at beginning of fragment zero if offset > 0.
        fragment -= 1;
        fragment_offset = length(fragment);
    }
    length(fragment) - fragment_offset <= offset
}

/// Whether the data of each entry of `za`, as read, ends before the local
/// header of the next.
fn entries_apart<R: ReadAt>(za: &Archive<R>, data: &[u8]) -> bool {
    let u16_at = |at: usize| u64::from(u16::from_le_bytes([data[at], data[at + 1]]));
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for i in 0..za.get_num_entries(Flags::UNCHANGED) {
        let (Ok(start), Ok(st)) = (za.file_get_offset(i), za.stat_index(i, Flags::UNCHANGED))
        else {
            return false;
        };
        // Where the local header whose data starts there starts: its name
        // and extra fields, as long as it says, come between.
        let header = (0..data.len().saturating_sub(29)).find(|&h| {
            data[h..h + 4] == *b"PK\x03\x04"
                && h as u64 + 30 + u16_at(h + 26) + u16_at(h + 28) == start
        });
        let Some(header) = header else {
            return false;
        };
        spans.push((header as u64, start + st.comp_size));
    }
    spans.sort_unstable();
    spans.windows(2).all(|w| w[0].1 <= w[1].0)
}

/// [`edit_ops_and_state`], then the archive written to a buffer source in
/// fragments of `fragment_size` bytes, as the oracle's `editb` has it.
fn edit_buffer(data: &[u8], flags: OpenFlags, fragment_size: u64, ops: &str) -> String {
    let mut za = match Archive::open(data, flags) {
        Ok(za) => za,
        Err(e) => return error_text(e),
    };
    let mut text = edit_ops_and_state(&mut za, ops);
    text.push_str(" |");
    let mut out = std::io::Cursor::new(Vec::new());
    let len = data.len() as u64;
    let expected = archive_state(&za, ops);
    let apart = entries_apart(&za, data);
    za.set_random_source(Some(oracle_random(ops)));
    match za.close_to_cloning(&mut out, |offset| {
        buffer_can_clone(len, fragment_size, offset)
    }) {
        Ok(Closed::Unchanged) => {
            let _ = write!(text, "buffer {}", hex(data));
        }
        Ok(Closed::Removed) => text.push_str("deleted"),
        Ok(Closed::Written) => {
            // What is kept is kept as it is: an entry before the first one
            // that changed is cut there if its data reaches past it.
            if !za.get_archive_flag(ArchiveFlags::WANT_TORRENTZIP, Flags::NONE) && apart {
                check_written(&expected, out.get_ref());
            }
            let _ = write!(text, "buffer {}", hex(out.get_ref()));
        }
        Err(e) => text.push_str(&error_text(e)),
    }
    text
}

/// The data of entry `i`, decompressed, if it reads.
fn entry_data<R: ReadAt>(za: &Archive<R>, i: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut zf = za.fopen_index(i, Flags::NONE).ok()?;
    let mut data = Vec::new();
    zf.read_to_end(&mut data).ok()?;
    Some(data)
}

/// The raw data of entry `i`, as stored.
fn raw_data<R: ReadAt>(za: &Archive<R>, i: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut zf = za.fopen_index(i, Flags::ENCRYPTED).ok()?;
    let mut data = Vec::new();
    zf.read_to_end(&mut data).ok()?;
    Some(data)
}

thread_local! {
    /// Whether [`check_written`] checks.
    static CHECK_WRITTEN: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// The port's answer to `request`: if a check of an archive written fails,
/// the answer without it, so that a difference from libzip shows first,
/// then the check's failure.
fn checked_answer(request: &str, want: &str) -> String {
    match std::panic::catch_unwind(|| answer(request)) {
        Ok(got) => got,
        Err(panic) => {
            CHECK_WRITTEN.with(|c| c.set(false));
            let got = answer(request);
            CHECK_WRITTEN.with(|c| c.set(true));
            assert_eq!(
                got, want,
                "libzip differs where the check failed: {request:.400}"
            );
            std::panic::resume_unwind(panic)
        }
    }
}

/// What the API says of an entry, as it is to be written.
struct EntryState {
    index: u64,
    name: Vec<u8>,
    comment: Vec<u8>,
    attributes: (u8, u32),
    /// as stored, which new data only has once written, from its source
    dos_time: Option<(u16, u16)>,
    stat: hivepack::zip::Stat<'static>,
    data: Option<Vec<u8>>,
    raw: Option<Vec<u8>>,
}

/// What the API says of an archive before it is written: the entries with
/// names, which are those written, and the archive comment; and from the
/// ops, the passwords they set and the entries they encrypt anew.
struct ArchiveState {
    entries: Vec<EntryState>,
    comment: Vec<u8>,
    passwords: Vec<Vec<u8>>,
    encryption_set: Vec<u64>,
}

fn archive_state<R: ReadAt>(za: &Archive<R>, ops: &str) -> ArchiveState {
    let (passwords, encryption_set) = encryption_ops(ops);
    let entries = (0..za.get_num_entries(Flags::NONE))
        .filter_map(|i| {
            let name = za.get_name(i, Flags::ENC_RAW).ok()?.to_vec();
            Some(EntryState {
                index: i,
                name,
                comment: za.file_get_comment(i, Flags::ENC_RAW).unwrap().to_vec(),
                attributes: za.file_get_external_attributes(i, Flags::NONE).unwrap(),
                // An entry with new data cannot be read raw.
                dos_time: match za.fopen_index(i, Flags::COMPRESSED) {
                    Err(e) if e.code() == ErrorCode::Changed => None,
                    _ => Some(za.file_get_dos_time(i, Flags::NONE).unwrap()),
                },
                stat: hivepack::zip::Stat {
                    name: None,
                    ..za.stat_index(i, Flags::NONE).unwrap()
                },
                data: entry_data(za, i),
                raw: raw_data(za, i),
            })
        })
        .collect();
    ArchiveState {
        entries,
        comment: za.get_archive_comment(Flags::ENC_RAW).to_vec(),
        passwords,
        encryption_set,
    }
}

/// Whether entry `j` reads as `data`, without a password or with one of
/// `passwords`.
fn reads_as<R: ReadAt>(za: &Archive<R>, j: u64, passwords: &[Vec<u8>], data: &[u8]) -> bool {
    use std::io::Read;
    let read = |password: Option<&[u8]>| -> Option<Vec<u8>> {
        let mut zf = za.fopen_index_encrypted(j, Flags::NONE, password).ok()?;
        let mut out = Vec::new();
        zf.read_to_end(&mut out).ok()?;
        Some(out)
    };
    std::iter::once(None)
        .chain(passwords.iter().map(|p| Some(&p[..])))
        .any(|password| read(password).as_deref() == Some(data))
}

/// That the archive `written` has the entries of `expected`, in order, as
/// they were edited: their names, comments, attributes, times, sizes and
/// data.
fn check_written(expected: &ArchiveState, written: &[u8]) {
    use hivepack::zip::stat;
    if !CHECK_WRITTEN.with(std::cell::Cell::get) {
        return;
    }
    // Something that looks like an end of central directory record, or a
    // Zip64 one or its locator, in a name, a comment, an extra field or the
    // data may be taken for the real one: libzip does not check that what
    // it writes reads back.
    let count = |signature: &[u8]| written.windows(4).filter(|&w| w == signature).count();
    let (eocd64, locator) = (count(b"PK\x06\x06"), count(b"PK\x06\x07"));
    if count(b"PK\x05\x06") > 1 || eocd64 > 1 || locator != eocd64 {
        return;
    }
    // Bytes before the record of an archive with no entries, kept from the
    // archive that was edited: _zip_read_cdir takes an empty archive only
    // from offset 0.
    if expected.entries.is_empty() && !written.starts_with(b"PK\x05\x06") {
        return;
    }
    let new = match Archive::open(written, OpenFlags(0)) {
        Ok(new) => new,
        Err(e) => panic!("the written archive does not open: {e} ({:?})", e.detail()),
    };
    // An entry deleted, then given changes (zip_set_file_compression and
    // others do not check), has its name again, though it is not written:
    // the API cannot tell it from one that is kept. The comparison with
    // libzip covers it.
    if new.get_num_entries(Flags::NONE) != expected.entries.len() as u64 {
        return;
    }
    for (j, e) in expected.entries.iter().enumerate() {
        let (i, j) = (e.index, j as u64);
        assert_eq!(new.get_name(j, Flags::ENC_RAW).unwrap(), e.name);
        assert_eq!(new.file_get_comment(j, Flags::ENC_RAW).unwrap(), e.comment);
        assert_eq!(
            new.file_get_external_attributes(j, Flags::NONE).unwrap(),
            e.attributes
        );
        let (a, b) = (new.stat_index(j, Flags::NONE).unwrap(), e.stat);
        // An entry compressed again, which has no compressed size until it
        // is, is stored differently, with the time of its stat (an MS-DOS
        // time out of range comes back in range), and, from
        // ZIP_CM_DEFAULT, deflated or stored.
        let recompressed = b.valid & stat::COMP_SIZE == 0;
        // An entry encrypted anew is read through the layers that decrypt
        // and decompress it, as one compressed again, so its time is that
        // of its stat; it has another compressed size and raw data, and is
        // read with its password.
        let reencrypted = expected.encryption_set.contains(&i)
            || (recompressed && b.encryption_method != hivepack::zip::em::NONE);
        if let Some(dos_time) = e.dos_time
            && !recompressed
            && !reencrypted
        {
            assert_eq!(new.file_get_dos_time(j, Flags::NONE).unwrap(), dos_time);
        }
        // What the edited archive knows: new data has the stat of its
        // source, which lacks what compressing gives, and the method the
        // entry had until it is written.
        let mut both = a.valid & b.valid;
        if e.dos_time.is_none() {
            both &= stat::SIZE | stat::CRC;
        }
        // The length of data compressed again is what it decompresses to,
        // which the header may have wrong.
        if recompressed {
            both &= stat::CRC;
        }
        // The layer that encrypts stops reading at the first short read,
        // so the data is never read to its end and its CRC never checked:
        // an entry encrypted anew takes the CRC and length of its data,
        // which the header may have wrong.
        if reencrypted {
            both &= stat::ENCRYPTION_METHOD;
            // An entry whose flags have the strong encryption bit keeps it
            // when encrypted, as in libzip, and reads back as encrypted
            // with an unknown method.
            if a.encryption_method == hivepack::zip::em::UNKNOWN {
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
                assert_eq!(x, y, "stat field {field:#x} of entry {i}");
            }
        }
        // Before it is written, new data is read with the method the entry
        // had, as libzip reads it. An entry compressed again and encrypted
        // with ZipCrypto from an MS-DOS time out of range cannot be read:
        // the header keeps the time, but the check byte comes from the time
        // of its stat, back in range, as in libzip.
        let check_byte_moved = recompressed
            && a.encryption_method == hivepack::zip::em::TRAD_PKWARE
            && e.dos_time
                .is_some_and(|(time, date)| !dos_time_in_range(time, date));
        // A WinZip AES entry of AE-2 written as AE-1 (see below) has its CRC
        // checked now, which AE-2 left as it was. And one encrypted with an
        // unknown method (see above) is decrypted by nothing.
        let crc_checked_now = a.valid & stat::CRC != 0 && b.valid & stat::CRC == 0;
        if let Some(data) = &e.data
            && e.dos_time.is_some()
            && !check_byte_moved
            && !crc_checked_now
            && a.encryption_method != hivepack::zip::em::UNKNOWN
        {
            assert!(
                reads_as(&new, j, &expected.passwords, data),
                "data of entry {i}"
            );
        }
        // A WinZip AES entry of AE-2, without a CRC, is written as AE-1 if
        // it has 20 bytes or more, and its CRC is then checked on reading,
        // on the encrypted data.
        let same_crc_check = a.valid & stat::CRC == b.valid & stat::CRC;
        if let Some(raw) = &e.raw
            && same_crc_check
            && !recompressed
            && !reencrypted
        {
            assert_eq!(
                raw_data(&new, j).as_ref(),
                Some(raw),
                "raw data of entry {i}"
            );
        }
    }
    // As in libzip, a comment removed is still given until the archive is
    // written.
    let comment = new.get_archive_comment(Flags::ENC_RAW);
    assert!(comment.is_empty() || comment == expected.comment);
}

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
    seconds < 30
        && minutes < 60
        && hours < 24
        && (1..=12).contains(&month)
        && (1..=days).contains(&day)
}

/// A path for a temporary archive of this process.
fn temporary_path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "hivepack-zip-{}-{}.zip",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// The port's answer to a request, in the oracle's format.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    if let ["editb", flags, fragment, ops, data] = words[..] {
        return edit_buffer(
            &unhex(data),
            OpenFlags(flags.parse().unwrap()),
            fragment.parse().unwrap(),
            ops,
        );
    }
    if let ["edit", flags, ops, data] = words[..] {
        let path = temporary_path();
        std::fs::write(&path, unhex(data)).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let text = match Archive::open(file, OpenFlags(flags.parse().unwrap())) {
            Ok(mut za) => edit_archive(&mut za, ops),
            Err(e) => error_text(e),
        };
        let _ = std::fs::remove_file(&path);
        return text;
    }
    let (flags, kind, data) = match words[..] {
        ["open", flags, kind, data] => (flags, kind, data),
        ["read", flags, kind, _, _, _, data] => (flags, kind, data),
        ["decrypt", flags, kind, _, _, _, _, _, data] => (flags, kind, data),
        ["range", flags, kind, _, _, data] => (flags, kind, data),
        _ => panic!("{request:.100}"),
    };
    let flags = OpenFlags(flags.parse().unwrap());
    let data = unhex(data);
    if kind == "f" {
        let path = temporary_path();
        std::fs::write(&path, &data).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let text = respond(&words, Archive::open(file, flags));
        let _ = std::fs::remove_file(&path);
        text
    } else {
        respond(&words, Archive::open(data.as_slice(), flags))
    }
}

/// One entry of a generated archive, as written in each header.
#[derive(Clone)]
struct Spec {
    name: Vec<u8>,
    local_name: Vec<u8>,
    gpbf: u16,
    local_gpbf: u16,
    method: u16,
    local_method: u16,
    time: u16,
    date: u16,
    local_time: u16,
    crc: u32,
    local_crc: u32,
    /// The size fields as written, 0xffffffff where the Zip64 field has it.
    csize: u32,
    usize: u32,
    local_csize: u32,
    local_usize: u32,
    data: Vec<u8>,
    central_extra: Vec<u8>,
    local_extra: Vec<u8>,
    comment: Vec<u8>,
    made_by: u16,
    needed: u16,
    local_needed: u16,
    int_attr: u16,
    ext_attr: u32,
    disk: u16,
    /// The offset field, `None` for the real one.
    offset: Option<u32>,
    /// The data descriptor after the data.
    descriptor: Vec<u8>,
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn field(out: &mut Vec<u8>, id: u16, data: &[u8]) {
    put16(out, id);
    put16(out, data.len() as u16);
    out.extend_from_slice(data);
}

/// A name or comment of some kind.
fn text(rng: &mut Rng, len: usize) -> Vec<u8> {
    let pieces: [&[u8]; 12] = [
        b"a",
        b"Readme",
        b".txt",
        b"/",
        b"dir/",
        b"\xc3\xa9",
        "日本".as_bytes(),
        "😀".as_bytes(),
        b"\x81\xe9",
        b"\x01",
        b" ",
        b"Z9",
    ];
    let mut out = Vec::new();
    while out.len() < len {
        match rng.below(12) {
            0 => out.push(rng.next() as u8),
            _ => out.extend_from_slice(rng.pick(&pieces)),
        }
    }
    out
}

fn name(rng: &mut Rng, earlier: &[Spec]) -> Vec<u8> {
    match rng.below(20) {
        0 => Vec::new(),
        1 => b"a\0b".to_vec(),
        2 | 3 if !earlier.is_empty() => earlier[rng.below(earlier.len() as u64) as usize]
            .name
            .clone(),
        4 if !earlier.is_empty() => earlier[rng.below(earlier.len() as u64) as usize]
            .name
            .to_ascii_uppercase(),
        5 => text(rng, 3).iter().map(|&b| b & 0x7f).collect(),
        6..=11 => {
            let parts = [
                &b"docs"[..],
                b"src",
                b"main.rs",
                b"README",
                b"x/y/z.txt",
                b"empty/",
            ];
            let mut name = rng.pick(&parts).to_vec();
            name.extend_from_slice(rng.below(1000).to_string().as_bytes());
            name
        }
        _ => {
            let len = 1 + rng.below(12) as usize;
            text(rng, len)
        }
    }
}

/// The Info-ZIP Unicode Path or Comment extra field for `of`.
fn unicode_field(rng: &mut Rng, id: u16, of: &[u8]) -> Vec<u8> {
    let mut data = vec![if rng.below(8) == 0 { 2 } else { 1 }];
    let crc = if rng.below(4) == 0 {
        rng.next() as u32
    } else {
        crc32(0, of)
    };
    put32(&mut data, crc);
    match rng.below(4) {
        0 => data.extend_from_slice(of),
        1 => data.extend_from_slice(&text(rng, 4).iter().map(|&b| b & 0x7f).collect::<Vec<_>>()),
        2 => data.extend_from_slice("ünïcödé".as_bytes()),
        _ => {
            let len = rng.below(6) as usize;
            data.extend_from_slice(&text(rng, len));
        }
    }
    if rng.below(10) == 0 {
        data.truncate(rng.below(6) as usize);
    }
    let mut out = Vec::new();
    field(&mut out, id, &data);
    out
}

/// Fields of no meaning to libzip.
fn other_fields(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..rng.below(3) {
        let id = rng.pick(&[0x5455u16, 0x7875, 0x000a, 0xcafe, 0x0002, 0x9901]);
        let len = rng.below(12) as usize;
        let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        field(&mut out, id, &data);
    }
    out
}

/// The uncompressed data of an entry: text, runs or random bytes.
fn plain(rng: &mut Rng) -> Vec<u8> {
    let len = rng.pick(&[0usize, 1, 5, 12, 40, 300, 3000, 20_000]);
    match rng.below(3) {
        0 => (0..len).map(|_| rng.next() as u8).collect(),
        1 => text(rng, len),
        _ => {
            let byte = rng.next() as u8;
            vec![byte; len]
        }
    }
}

/// `plain` as a raw deflate stream, from the port's compressor, which
/// writes zlib's streams.
fn deflated(rng: &mut Rng, plain: &[u8]) -> Vec<u8> {
    let level = rng.below(10) as i32;
    let mut stream = Deflate::new(level, -15, 8, 0).unwrap();
    let mut out = vec![0; stream.bound(plain.len() as u64) as usize];
    let mut output = OutBuffer::new(&mut out);
    let ret = stream.deflate(&mut output, &mut InBuffer::new(plain), DeflateFlush::Finish);
    assert_eq!(ret, Ok(DeflateStatus::StreamEnd));
    let written = output.pos;
    out.truncate(written);
    out
}

/// `plain` as a bzip2 stream, at a random block size.
fn bzipped(rng: &mut Rng, plain: &[u8]) -> Vec<u8> {
    let mut out = vec![0; plain.len() + plain.len() / 64 + 1024];
    let len = hivepack::bzip2::buff_to_buff_compress(&mut out, plain, 1 + rng.below(9) as i32, 0)
        .unwrap();
    out.truncate(len);
    out
}

/// The flags of a Zstandard entry: mostly the quicker levels; now and then
/// the slowest, and those past the ends, which leave the level to libzstd.
/// Negative ones are among those: `zip_set_file_compression` cuts the flags
/// to a `u16`.
fn zstd_flags(rng: &mut Rng) -> u32 {
    match rng.below(4) {
        0 => rng.pick(&[
            -131_073i32,
            -131_072,
            -100,
            -5,
            -1,
            13,
            16,
            19,
            22,
            23,
            65_535,
        ]) as u32,
        _ => rng.below(10) as u32,
    }
}

/// `plain` as a ZIP entry's LZMA data, at a random preset: the magic, the
/// properties, and the data, with the end of stream marker that liblzma's
/// .lzma encoder writes (`true`), or without it, from raw LZMA1EXT.
fn lzma_zipped(rng: &mut Rng, plain: &[u8]) -> (Vec<u8>, bool) {
    let options = hivepack::xz::LzmaOptions::preset(rng.below(4) as u32).unwrap();
    let eos = rng.below(3) != 0;
    let mut out = vec![0; plain.len() + plain.len() / 2 + 4096];
    let mut output = hivepack::xz::OutBuffer::new(&mut out);
    let mut input = hivepack::xz::InBuffer::new(plain);
    let mut strm = if eos {
        hivepack::xz::Stream::alone_encoder(&options).unwrap()
    } else {
        hivepack::xz::Stream::raw_encoder(&[hivepack::xz::Filter {
            id: hivepack::xz::FILTER_LZMA1EXT,
            options: Some(hivepack::xz::FilterOptions::Lzma(options.clone())),
        }])
        .unwrap()
    };
    let ret = strm.code(&mut output, &mut input, hivepack::xz::Action::Finish);
    assert_eq!(ret, Ok(hivepack::xz::Status::StreamEnd));
    let len = output.pos;
    let mut data = vec![0x09, 0x14, 0x05, 0x00];
    if eos {
        data.extend_from_slice(&out[..5]);
        data.extend_from_slice(&out[13..len]);
    } else {
        data.push(((options.pb * 5 + options.lp) * 9 + options.lc) as u8);
        data.extend_from_slice(&options.dict_size.to_le_bytes());
        data.extend_from_slice(&out[..len]);
    }
    (data, eos)
}

/// `plain` as an .xz Stream, at a random preset, with a random check.
fn xzed(rng: &mut Rng, plain: &[u8]) -> Vec<u8> {
    let mut out = vec![0; hivepack::xz::stream_buffer_bound(plain.len())];
    let mut len = 0;
    hivepack::xz::easy_buffer_encode(
        rng.below(4) as u32,
        hivepack::xz::Check(rng.pick(&[0, 1, 4, 10])),
        plain,
        &mut out,
        &mut len,
    )
    .unwrap();
    out.truncate(len);
    out
}

/// `plain` as Zstandard frames at a random level, with a checksum and the
/// content size or not: now and then in two frames, after a skippable one.
fn zstded(rng: &mut Rng, plain: &[u8]) -> Vec<u8> {
    use hivepack::zstd::{CCtx, CParameter};
    let mut out = Vec::new();
    if rng.below(8) == 0 {
        let skip = rng.below(20) as u32;
        out.extend_from_slice(&(0x184d_2a50 + rng.below(16) as u32).to_le_bytes());
        out.extend_from_slice(&skip.to_le_bytes());
        out.extend((0..skip).map(|_| rng.next() as u8));
    }
    let at = match rng.below(8) {
        0 => rng.below(plain.len() as u64 + 1) as usize,
        _ => plain.len(),
    };
    let (first, second) = plain.split_at(at);
    for (i, part) in [first, second].into_iter().enumerate() {
        if i == 1 && part.is_empty() {
            break;
        }
        let mut cctx = CCtx::new();
        let level = rng.below(6) as i32 - 1;
        cctx.set_parameter(CParameter::CompressionLevel(level))
            .unwrap();
        cctx.set_parameter(CParameter::ChecksumFlag(rng.below(2) == 0))
            .unwrap();
        cctx.set_parameter(CParameter::ContentSizeFlag(rng.below(2) == 0))
            .unwrap();
        let mut frame = vec![0; hivepack::zstd::compress_bound(part.len()).unwrap()];
        let len = cctx.compress2(&mut frame, part).unwrap();
        out.extend_from_slice(&frame[..len]);
    }
    out
}

fn spec(rng: &mut Rng, earlier: &[Spec]) -> Spec {
    let name = name(rng, earlier);
    let method = rng.pick(&[0u16, 0, 0, 8, 8, 8, 9, 12, 14, 95, 93, 99, 97]);
    let plain = plain(rng);
    let mut lzma_eos = false;
    let data = match method {
        0 => plain.clone(),
        8 | 12 | 14 | 93 | 95 => {
            let mut data = match method {
                8 => deflated(rng, &plain),
                12 => bzipped(rng, &plain),
                14 => {
                    let (data, eos) = lzma_zipped(rng, &plain);
                    lzma_eos = eos;
                    data
                }
                93 => zstded(rng, &plain),
                _ => xzed(rng, &plain),
            };
            match rng.below(12) {
                // Cut short, garbage after it, or a byte changed.
                0 => data.truncate(rng.below(data.len() as u64 + 1) as usize),
                1 => data.extend((0..1 + rng.below(4)).map(|_| rng.next() as u8)),
                2 if !data.is_empty() => {
                    let at = rng.below(data.len() as u64) as usize;
                    data[at] ^= 1 << rng.below(8);
                }
                _ => {}
            }
            data
        }
        _ => (0..plain.len().min(40)).map(|_| rng.next() as u8).collect(),
    };
    let data_len = data.len();
    let mut gpbf = 0u16;
    // Now and then what the data does not have.
    if lzma_eos != (rng.below(12) == 0) {
        gpbf |= 0x0002;
    }
    if rng.below(3) == 0 {
        gpbf |= 0x0800;
    }
    if rng.below(6) == 0 {
        gpbf |= 0x0008;
    }
    if rng.below(8) == 0 {
        gpbf |= 0x0001;
        if rng.below(4) == 0 {
            gpbf |= 0x0040;
        }
    }
    let encrypted_header = if gpbf & 1 != 0 { 12 } else { 0 };
    let usize = match rng.below(10) {
        0 => rng.next() as u32 % 100,
        1 => plain.len() as u32 + 1,
        _ if method == 0 => (data_len as u32).saturating_sub(encrypted_header),
        _ => plain.len() as u32,
    };
    let crc = if rng.below(8) == 0 {
        rng.next() as u32
    } else {
        crc32(0, &plain)
    };
    let time = rng.next() as u16;
    let date = rng.next() as u16;
    let mut central_extra = Vec::new();
    let mut local_extra = Vec::new();
    if rng.below(4) == 0 {
        central_extra.extend(unicode_field(rng, 0x7075, &name));
    }
    if rng.below(8) == 0 {
        local_extra.extend(unicode_field(rng, 0x7075, &name));
    }
    let comment = match rng.below(6) {
        0 => text(rng, 5),
        1 => b"note".to_vec(),
        _ => Vec::new(),
    };
    if rng.below(8) == 0 {
        central_extra.extend(unicode_field(rng, 0x6375, &comment));
    }
    if method == 99 || rng.below(20) == 0 {
        let mut aes = Vec::new();
        put16(&mut aes, rng.pick(&[1, 2, 2, 3]));
        aes.extend_from_slice(rng.pick(&[&b"AE"[..], b"AE", b"XY"]));
        aes.push(rng.pick(&[1, 2, 3, 3, 4]));
        put16(&mut aes, rng.pick(&[0, 8, 8]));
        if rng.below(10) == 0 {
            aes.push(0);
        }
        let mut f = Vec::new();
        field(&mut f, 0x9901, &aes);
        central_extra.extend_from_slice(&f);
        if rng.below(2) == 0 {
            local_extra.extend_from_slice(&f);
        }
    }
    central_extra.extend(other_fields(rng));
    local_extra.extend(other_fields(rng));
    for extra in [&mut central_extra, &mut local_extra] {
        match rng.below(20) {
            0 => extra.extend(std::iter::repeat_n(0, 1 + rng.below(3) as usize)),
            1 => extra.push(rng.next() as u8),
            2 => extra.extend_from_slice(&[0x01, 0x02, 0x40, 0x00]),
            _ => {}
        }
    }
    let needed = rng.pick(&[10u16, 20, 20, 45, 63]);
    let descriptor_sizes = gpbf & 0x0008 != 0;
    let mut s = Spec {
        local_name: name.clone(),
        name,
        gpbf,
        local_gpbf: gpbf,
        method,
        local_method: method,
        time,
        date,
        local_time: time,
        crc,
        local_crc: if descriptor_sizes && rng.below(2) == 0 {
            0
        } else {
            crc
        },
        csize: data_len as u32,
        usize,
        local_csize: if descriptor_sizes && rng.below(2) == 0 {
            0
        } else {
            data_len as u32
        },
        local_usize: if descriptor_sizes && rng.below(2) == 0 {
            0
        } else {
            usize
        },
        data,
        central_extra,
        local_extra,
        comment,
        made_by: rng.pick(&[0x031e, 0x0014, 0x0a3f, 0x1314]),
        needed,
        local_needed: needed,
        int_attr: rng.pick(&[0, 1]),
        ext_attr: rng.next() as u32,
        disk: 0,
        offset: None,
        descriptor: Vec::new(),
    };
    // The local header disagrees now and then.
    match rng.below(25) {
        0 => s.local_name = b"other".to_vec(),
        1 => s.local_time ^= 1,
        2 => s.local_needed += 1,
        3 => s.local_method ^= 8,
        4 => s.local_crc ^= 1,
        5 => s.local_gpbf ^= 0x0008,
        6 => s.disk = rng.pick(&[1, 0xffff]),
        7 => s.offset = Some(rng.next() as u32 % 200),
        _ => {}
    }
    if s.local_gpbf & 0x0008 != 0 && rng.below(6) != 0 {
        let mut dd = Vec::new();
        if rng.below(2) == 0 {
            dd.extend_from_slice(b"PK\x07\x08");
        }
        put32(&mut dd, s.crc);
        put32(&mut dd, s.csize);
        put32(&mut dd, s.usize);
        if rng.below(8) == 0 {
            let last = dd.len() - 1;
            dd[last] ^= 1;
        }
        s.descriptor = dd;
    }
    s
}

/// Moves sizes and the offset into Zip64 extra fields, as Zip64 writers
/// do, sometimes not quite right.
fn zip64_fields(rng: &mut Rng, s: &mut Spec, offset: u64) {
    let mut central = Vec::new();
    let mut local = Vec::new();
    let (usize, csize) = (u64::from(s.usize), u64::from(s.csize));
    let all = rng.below(3) == 0;
    if all || rng.below(2) == 0 {
        put64(&mut central, usize);
        s.usize = u32::MAX;
    }
    if all || rng.below(2) == 0 {
        put64(&mut central, csize);
        s.csize = u32::MAX;
    }
    if all || rng.below(2) == 0 {
        put64(&mut central, offset);
        s.offset = Some(u32::MAX);
    }
    if rng.below(4) == 0 {
        put32(&mut central, 0);
        s.disk = 0xffff;
    }
    match rng.below(12) {
        0 => central.truncate(central.len().saturating_sub(4)),
        1 => central.extend_from_slice(&[0; 8]),
        2 => {
            central.clear();
            put64(&mut central, usize);
            put64(&mut central, csize);
            put64(&mut central, offset);
            if rng.below(2) == 0 {
                put32(&mut central, 0);
            }
        }
        _ => {}
    }
    if rng.below(6) != 0 {
        let mut f = Vec::new();
        field(&mut f, 0x0001, &central);
        s.central_extra.splice(0..0, f);
    }
    if rng.below(2) == 0 {
        put64(&mut local, usize);
        put64(&mut local, csize);
        s.local_usize = u32::MAX;
        s.local_csize = u32::MAX;
        let mut f = Vec::new();
        field(&mut f, 0x0001, &local);
        s.local_extra.splice(0..0, f);
    }
}

fn write_local(out: &mut Vec<u8>, s: &Spec) {
    out.extend_from_slice(b"PK\x03\x04");
    put16(out, s.local_needed);
    put16(out, s.local_gpbf);
    put16(out, s.local_method);
    put16(out, s.local_time);
    put16(out, s.date);
    put32(out, s.local_crc);
    put32(out, s.local_csize);
    put32(out, s.local_usize);
    put16(out, s.local_name.len() as u16);
    put16(out, s.local_extra.len() as u16);
    out.extend_from_slice(&s.local_name);
    out.extend_from_slice(&s.local_extra);
    out.extend_from_slice(&s.data);
    out.extend_from_slice(&s.descriptor);
}

fn write_central(out: &mut Vec<u8>, s: &Spec, offset: u32) {
    out.extend_from_slice(b"PK\x01\x02");
    put16(out, s.made_by);
    put16(out, s.needed);
    put16(out, s.gpbf);
    put16(out, s.method);
    put16(out, s.time);
    put16(out, s.date);
    put32(out, s.crc);
    put32(out, s.csize);
    put32(out, s.usize);
    put16(out, s.name.len() as u16);
    put16(out, s.central_extra.len() as u16);
    put16(out, s.comment.len() as u16);
    put16(out, s.disk);
    put16(out, s.int_attr);
    put32(out, s.ext_attr);
    put32(out, s.offset.unwrap_or(offset));
    out.extend_from_slice(&s.name);
    out.extend_from_slice(&s.central_extra);
    out.extend_from_slice(&s.comment);
}

/// A generated archive.
fn archive(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    let prefix = rng.below(10) == 0;
    if prefix {
        out.extend((0..1 + rng.below(60)).map(|_| rng.next() as u8));
    }
    let count = match rng.below(10) {
        0 => 0,
        1 => 10 + rng.below(30),
        _ => 1 + rng.below(5),
    } as usize;
    let zip64 = rng.below(6) == 0;
    let mut specs: Vec<Spec> = Vec::new();
    let mut offsets = Vec::new();
    for _ in 0..count {
        let mut s = spec(rng, &specs);
        let offset = out.len() as u64;
        if zip64 && rng.below(2) == 0 {
            zip64_fields(rng, &mut s, offset);
        }
        // A self-extractor that does not count its prefix.
        let written = if prefix && rng.below(2) == 0 {
            offset.saturating_sub(10)
        } else {
            offset
        };
        write_local(&mut out, &s);
        offsets.push(written as u32);
        specs.push(s);
    }
    let cd_offset = out.len() as u64;
    let mut central = Vec::new();
    for (s, &offset) in specs.iter().zip(&offsets) {
        write_central(&mut central, s, offset);
    }
    out.extend_from_slice(&central);
    let cd_size = central.len() as u64;

    let mut entries = count as u64;
    let mut size = cd_size;
    let mut offset = cd_offset;
    match rng.below(20) {
        0 => entries += 1,
        1 => entries = entries.saturating_sub(1),
        2 => size += 1,
        3 => offset = offset.saturating_sub(1),
        4 => offset += 3,
        _ => {}
    }
    let mut disks = [0u16, 0];
    if rng.below(25) == 0 {
        disks[rng.below(2) as usize] = rng.pick(&[1, 2, 0xffff]);
    }
    let mut this_disk_entries = entries;
    if rng.below(30) == 0 {
        this_disk_entries ^= 1;
    }

    if zip64 {
        let eocd64 = out.len() as u64;
        out.extend_from_slice(b"PK\x06\x06");
        put64(&mut out, if rng.below(15) == 0 { 40 } else { 44 });
        put16(&mut out, 45);
        put16(&mut out, 45);
        put32(&mut out, u32::from(disks[0]));
        put32(&mut out, u32::from(disks[1]));
        put64(&mut out, this_disk_entries);
        put64(
            &mut out,
            if rng.below(20) == 0 {
                entries * 100
            } else {
                entries
            },
        );
        put64(&mut out, size);
        put64(&mut out, offset);
        if rng.below(15) == 0 {
            out.extend_from_slice(&[0; 4]);
        }
        out.extend_from_slice(b"PK\x06\x07");
        put32(&mut out, u32::from(disks[1]));
        put64(
            &mut out,
            if rng.below(15) == 0 {
                eocd64 + 1
            } else {
                eocd64
            },
        );
        put32(&mut out, if rng.below(20) == 0 { 2 } else { 1 });
    }

    let comment = match rng.below(12) {
        0 => {
            let crc = if rng.below(3) == 0 {
                rng.next() as u32
            } else {
                crc32(0, &central)
            };
            let mut c = b"TORRENTZIPPED-".to_vec();
            let digits = format!("{crc:08X}");
            c.extend_from_slice(
                if rng.below(6) == 0 {
                    digits.to_lowercase()
                } else {
                    digits
                }
                .as_bytes(),
            );
            c
        }
        1 => b"has PK\x05\x06 in it".to_vec(),
        2..=4 => text(rng, 8),
        _ => Vec::new(),
    };
    let mut eocd_entries = |n: u64| {
        if zip64 && rng.below(2) == 0 {
            0xffff
        } else {
            n as u16
        }
    };
    out.extend_from_slice(b"PK\x05\x06");
    put16(&mut out, disks[0]);
    put16(&mut out, disks[1]);
    put16(&mut out, eocd_entries(this_disk_entries));
    put16(&mut out, eocd_entries(entries));
    put32(
        &mut out,
        if zip64 && rng.below(2) == 0 {
            u32::MAX
        } else {
            size as u32
        },
    );
    put32(
        &mut out,
        if zip64 && rng.below(2) == 0 {
            u32::MAX
        } else {
            offset as u32
        },
    );
    let comment_len = match rng.below(15) {
        0 => comment.len() as u16 + 3,
        1 => (comment.len() as u16).saturating_sub(1),
        _ => comment.len() as u16,
    };
    put16(&mut out, comment_len);
    out.extend_from_slice(&comment);
    if rng.below(15) == 0 {
        out.extend((0..1 + rng.below(30)).map(|_| rng.next() as u8));
    }
    out
}

/// `count` open requests on generated archives, some damaged.
fn requests(rng: &mut Rng, count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let mut zip = archive(rng);
            if rng.below(4) == 0 {
                zip = damage(rng, &zip);
            }
            let flags = rng.pick(&[0, 4]);
            let kind = if rng.below(10) == 0 { "f" } else { "b" };
            format!("open {flags} {kind} {}", hex(&zip))
        })
        .collect()
}

/// `count` read requests on generated archives, some damaged: in pieces of
/// every size, with each flag that changes what is read, sometimes stopping
/// early.
fn read_requests(rng: &mut Rng, count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let mut zip = archive(rng);
            if rng.below(6) == 0 {
                zip = damage(rng, &zip);
            }
            format!("read {} {}", read_parameters(rng), hex(&zip))
        })
        .collect()
}

/// `count` range requests on generated archives, some damaged.
fn range_requests(rng: &mut Rng, count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let mut zip = archive(rng);
            if rng.below(6) == 0 {
                zip = damage(rng, &zip);
            }
            format!("range {} {}", range_parameters(rng), hex(&zip))
        })
        .collect()
}

/// `count` edit requests on generated archives, some damaged: a few edits
/// of every kind, to entries that are there and some that are not, with
/// names and comments taken from the archive or made up.
fn edit_requests(rng: &mut Rng, count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            // Mostly none or ZIP_CHECKCONS, and ZIP_RDONLY, ZIP_CREATE,
            // ZIP_EXCL, ZIP_TRUNCATE, both of the last and ZIP_RDONLY with
            // ZIP_TRUNCATE.
            let flags = match rng.below(14) {
                0..=7 => 0,
                8 | 9 => 4,
                _ => rng.pick(&[16, 1, 2, 8, 9, 24]),
            };
            let mut zip = archive(rng);
            if rng.below(8) == 0 {
                zip = damage(rng, &zip);
            } else {
                // Mostly archives libzip opens, with entries, so that the
                // edits are made and the archive written.
                for _ in 0..50 {
                    if Archive::open(zip.as_slice(), OpenFlags(flags))
                        .is_ok_and(|za| za.get_num_entries(Flags::NONE) > 0)
                    {
                        break;
                    }
                    zip = archive(rng);
                }
            }
            let ops = edit_ops(rng, &zip);
            format!("edit {flags} {ops} {}", hex(&zip))
        })
        .collect()
}

/// `count` `editb` requests: as [`edit_requests`], on buffers of every
/// fragment size.
fn editb_requests(rng: &mut Rng, count: usize) -> Vec<String> {
    edit_requests(rng, count)
        .into_iter()
        .map(|request| {
            let (flags, rest) = request["edit ".len()..].split_once(' ').unwrap();
            let fragment = rng.pick(&[0, 0, 1, 7, 50, 100, 256, 1000, 4096]);
            format!("editb {flags} {fragment} {rest}")
        })
        .collect()
}

/// A time for new data: in DOS range, before 1980 or past 2107.
fn new_mtime(rng: &mut Rng) -> i64 {
    match rng.below(4) {
        0 => rng.pick(&[0, 315_532_800, 4_354_819_200, -1]),
        _ => 315_532_800 + rng.below(4_000_000_000) as i64,
    }
}

/// New data for an entry: empty, text, runs, or bytes that do not compress,
/// some longer than the 8 KiB libzip reads at a time.
fn new_data(rng: &mut Rng) -> Vec<u8> {
    match rng.below(7) {
        0 => Vec::new(),
        1 => {
            let len = 1 + rng.below(60) as usize;
            text(rng, len)
        }
        2 => vec![b'a'; rng.pick(&[1, 10, 300, 9000])],
        3 => (0..rng.pick(&[5, 100, 8192, 8193]))
            .map(|_| rng.next() as u8)
            .collect(),
        4 => (0..20_000u32).map(|i| (i * 7 % 251) as u8).collect(),
        _ => plain(rng),
    }
}

/// The edits of an edit request on `zip`.
fn edit_ops(rng: &mut Rng, zip: &[u8]) -> String {
    let mut names = Vec::new();
    let mut comments = Vec::new();
    let mut attributes = Vec::new();
    if let Ok(za) = Archive::open(zip, OpenFlags(0)) {
        for i in 0..za.get_num_entries(Flags::NONE) {
            names.push(za.get_name(i, Flags::ENC_RAW).unwrap().to_vec());
            comments.push(za.file_get_comment(i, Flags::ENC_RAW).unwrap().to_vec());
            attributes.push(za.file_get_external_attributes(i, Flags::NONE).unwrap());
        }
    }
    let n = names.len() as u64;
    let some = |rng: &mut Rng, of: &[Vec<u8>]| -> Vec<u8> {
        if of.is_empty() {
            Vec::new()
        } else {
            of[rng.below(of.len() as u64) as usize].clone()
        }
    };
    let made_up = |rng: &mut Rng| -> Vec<u8> {
        match rng.below(8) {
            0 => Vec::new(),
            1 => b"a\0b".to_vec(),
            2 => "naïve/".as_bytes().to_vec(),
            3 => b"caf\xe9".to_vec(),
            _ => {
                let len = 1 + rng.below(12) as usize;
                text(rng, len)
            }
        }
    };
    let encoding = |rng: &mut Rng| rng.pick(&[0, 0, 0, 64, 2048, 4096, 6144]);

    let mut ops = Vec::new();
    let count = match rng.below(10) {
        0 => 0,
        _ => 1 + rng.below(6),
    };
    for _ in 0..count {
        let i = match rng.below(10) {
            0 => n + rng.below(3),
            _ => rng.below(n.max(1)),
        };
        let op = match rng.below(29) {
            0..=2 => format!("d{i}"),
            3..=5 => {
                let name = match rng.below(5) {
                    0 => some(rng, &names),
                    1 => {
                        let mut name = some(rng, &names);
                        name.push(b'/');
                        name
                    }
                    _ => made_up(rng),
                };
                format!("r{i}:{}:{}", hex(&name), encoding(rng))
            }
            6 | 7 => {
                let comment = match rng.below(4) {
                    0 => some(rng, &comments),
                    1 => some(rng, &names),
                    _ => made_up(rng),
                };
                format!("c{i}:{}:{}", hex(&comment), encoding(rng))
            }
            8 => {
                let comment = match rng.below(3) {
                    0 => Vec::new(),
                    _ => made_up(rng),
                };
                format!("a{}", hex(&comment))
            }
            9 => format!("t{i}:{}:{}", rng.below(65536), rng.below(65536)),
            10 => {
                let mtime: i64 = match rng.below(3) {
                    0 => rng.next() as i64 >> rng.below(64),
                    _ => rng.pick(&[
                        0,
                        -1,
                        315_532_800,
                        1_000_000_001,
                        1_793_277_296,
                        4_102_444_800,
                        4_354_819_200,
                        -2_208_988_800,
                        1 << 40,
                        67_767_976_233_532_799,
                        67_768_036_191_676_800,
                        -67_768_040_609_740_800,
                        i64::MAX,
                        i64::MIN,
                    ]),
                };
                format!("m{i}:{mtime}")
            }
            11 => {
                let (opsys, attr) = match attributes.get(i as usize) {
                    Some(&(opsys, attr)) if rng.below(2) == 0 => (opsys, attr),
                    _ => (rng.below(21) as u8, rng.next() as u32),
                };
                format!("x{i}:{opsys}:{attr}")
            }
            12 => format!("u{i}"),
            13 => rng.pick(&["U", "A"]).to_string(),
            14 | 15 => {
                // ZIP_FL_LOCAL, ZIP_FL_CENTRAL or both, or neither.
                let flags = rng.pick(&[256, 512, 768, 768, 0]);
                let id = rng.pick(&[0x5455u16, 0xcafe, 0x7875, 0x0001, 0x7075, 0x000a]);
                let idx = rng.pick(&[0, 0, 1, 2, 0xffff]);
                let len = rng.pick(&[0, 1, 4, 30]);
                let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                format!("e{i}:{id}:{idx}:{}:{flags}", hex(&data))
            }
            16 => {
                let flags = rng.pick(&[256, 512, 768, 0]);
                let id = rng.pick(&[0x5455u16, 0xcafe, 0x7875, 0x000a, 0xffff]);
                let idx = rng.pick(&[0, 1, 0xffff]);
                format!("E{i}:{id}:{idx}:{flags}")
            }
            17 => {
                let flags = rng.pick(&[256, 512, 768, 0]);
                let idx = rng.pick(&[0, 1, 2, 0xffff]);
                format!("D{i}:{idx}:{flags}")
            }
            18..=20 => {
                let name = match rng.below(4) {
                    0 => some(rng, &names),
                    _ => made_up(rng),
                };
                // 0, ZIP_FL_OVERWRITE, ZIP_FL_ENC_UTF_8 or ZIP_FL_ENC_CP437
                let flags = rng.pick(&[0, 0, 8192, 2048, 4096]);
                format!(
                    "+{}:{flags}:{}:{}:{}",
                    hex(&name),
                    new_mtime(rng),
                    hex(&new_data(rng)),
                    rng.pick(&["s", "s", "s", "u"])
                )
            }
            21 => format!(
                "R{i}:{}:{}:{}",
                new_mtime(rng),
                hex(&new_data(rng)),
                rng.pick(&["s", "s", "u"])
            ),
            22 => {
                let name = match rng.below(3) {
                    0 => some(rng, &names),
                    _ => made_up(rng),
                };
                format!(
                    "N{}:0:{}:{}",
                    hex(&name),
                    rng.below(65536),
                    rng.below(65536)
                )
            }
            25 | 26 => {
                // none, ZipCrypto, WinZip AES, and an unknown method
                let method = rng.pick(&[0, 1, 1, 257, 258, 259, 99]);
                let password = match rng.below(4) {
                    0 => "-".to_string(),
                    _ => hex(rng.pick(PASSWORDS)),
                };
                format!("y{i}:{method}:{password}")
            }
            27 => match rng.below(4) {
                0 => "P-".to_string(),
                _ => format!("P{}", hex(rng.pick(PASSWORDS))),
            },
            23 | 24 => {
                // stored, deflated, the default, bzip2, and methods there
                // are no compressors for, or that wrap to deflate as a u16
                let method: i64 = rng.pick(&[
                    0, 8, 8, -1, -1, 12, 12, 14, 14, 95, 95, 93, 93, 9, 65544, 99,
                ]);
                let flags = match method {
                    93 => zstd_flags(rng),
                    _ => rng.pick(&[0, 0, 1, 3, 6, 9, 10, 0xffff, 0x1_0005]),
                };
                format!("z{i}:{method}:{flags}")
            }
            _ => {
                // IS_TORRENTZIP (refused), WANT_TORRENTZIP,
                // CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE, RDONLY
                let flag = rng.pick(&[4, 8, 8, 16, 2]);
                format!("f{flag}:{}", rng.below(2))
            }
        };
        ops.push(op);
    }
    if ops.is_empty() {
        "-".to_string()
    } else {
        ops.join(",")
    }
}

/// The flags, source, start and length of a range request.
fn range_parameters(rng: &mut Rng) -> String {
    let flags = rng.pick(&[0, 4]);
    let kind = if rng.below(10) == 0 { "f" } else { "b" };
    let start = rng.pick(&[0, 0, 1, 3, 10, 100, 2000]);
    let len: i64 = match rng.below(4) {
        0 => -1,
        1 => 0,
        _ => rng.pick(&[1, 2, 5, 40, 300, 5000]),
    };
    format!("{flags} {kind} {start} {len}")
}

/// The flags, source, file flags, pieces and limit of a read request.
fn read_parameters(rng: &mut Rng) -> String {
    let flags = rng.pick(&[0, 4]);
    let kind = if rng.below(10) == 0 { "f" } else { "b" };
    // 0, ZIP_FL_COMPRESSED, ZIP_FL_ENCRYPTED, ZIP_FL_UNCHANGED
    let fflags = rng.pick(&[0, 0, 0, 4, 32, 8]);
    let chunks = rng.pick(&["8192", "1", "7,100", "65536", "3,5000,1", "20000"]);
    let limit = match rng.below(5) {
        0 => rng.below(100) as i64,
        1 => rng.pick(&[5, 12, 40, 300, 3000, 20_000]),
        _ => -1,
    };
    format!("{flags} {kind} {fflags} {chunks} {limit}")
}

/// The passwords the encrypted archives are written and read with: short,
/// past a block of SHA-1, with bytes past ASCII, and with a NUL byte, where
/// libzip's C string ends.
const PASSWORDS: &[&[u8]] = &[
    b"foo",
    b"p",
    b"correct horse battery staple, and some more words to pass 64 bytes",
    b"\xe9t\xe9",
    b"pass\0word",
];

/// An archive libzip writes from an empty buffer, through the oracle's
/// `editb` request: entries with data of each kind, up to `max_len` bytes,
/// some stored and some deflated, most encrypted with ZipCrypto or WinZip
/// AES, each with its password or the default one; with the passwords
/// they were written with. `None` if libzip did not write it.
fn encrypted_archive(
    oracle: &mut Oracle,
    rng: &mut Rng,
    max_len: u64,
) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let (ops, passwords) = encrypting_ops(rng, max_len);
    let reply = oracle.ask(&format!("editb 0 0 {ops} -"));
    let (_, written) = written_part(&reply)?;
    Some((unhex(written), passwords))
}

/// The ops of an edit request that makes an archive of encrypted entries
/// from an empty one, as [`encrypted_archive`] describes, and the
/// passwords it sets.
fn encrypting_ops(rng: &mut Rng, max_len: u64) -> (String, Vec<Vec<u8>>) {
    let mut ops = Vec::new();
    let mut passwords = Vec::new();
    let default = (rng.below(4) == 0).then(|| rng.pick(PASSWORDS));
    if let Some(password) = default {
        ops.push(format!("P{}", hex(password)));
    }
    for i in 0..1 + rng.below(4) {
        let len = match rng.below(4) {
            0 => rng.pick(&[0, 1, 10, 11, 12, 13, 16, 20, 64, 65]),
            1 => rng.below(200),
            2 => rng.below(max_len),
            _ => rng.pick(&[8191, 8192, 8193, 16384, 20000]),
        }
        .min(max_len) as usize;
        let data: Vec<u8> = match rng.below(3) {
            0 => (0..len).map(|i| b"encrypted zip data "[i % 19]).collect(),
            1 => (0..len).map(|_| rng.next() as u8).collect(),
            _ => vec![rng.next() as u8; len],
        };
        let mtime = 1_000_000_000 + rng.below(500_000_000);
        let kind = if rng.below(5) == 0 { "u" } else { "s" };
        let name = hex(format!("e{i}").as_bytes());
        ops.push(format!("+{name}:0:{mtime}:{}:{kind}", hex(&data)));
        match rng.below(5) {
            0 => ops.push(format!("z{i}:0:0")),
            1 => ops.push(format!("z{i}:8:{}", rng.below(10))),
            2 => ops.push(format!(
                "z{i}:{}:{}",
                rng.pick(&[12, 14, 93, 95]),
                rng.below(10)
            )),
            _ => {}
        }
        let method = rng.pick(&[0u16, 1, 1, 257, 258, 259, 259]);
        if method != 0 {
            let password = match default {
                Some(_) if rng.below(3) == 0 => None,
                _ => Some(rng.pick(PASSWORDS)),
            };
            ops.push(format!(
                "y{i}:{method}:{}",
                password.map_or("-".into(), hex)
            ));
            if let Some(password) = password.or(default) {
                passwords.push(password.to_vec());
            }
        }
    }
    (ops.join(","), passwords)
}

/// `count` edit requests that encrypt: libzip's archives of encrypted
/// entries made from nothing, which the port must write byte for byte with
/// the oracle's random bytes, then those archives changed: entries
/// encrypted anew with another method or password, or no longer, the
/// default password set (right or wrong) to compress them again,
/// ZipCrypto entries given another time, entries unchanged, replaced, or
/// given a comment.
fn encrypt_requests(oracle: &mut Oracle, rng: &mut Rng, count: usize, max_len: u64) -> Vec<String> {
    let mut requests = Vec::new();
    while requests.len() < count {
        let (ops, _) = encrypting_ops(rng, max_len);
        requests.push(format!("editb 0 0 {ops} -"));
        let Some((zip, passwords)) = encrypted_archive(oracle, rng, max_len) else {
            continue;
        };
        let n = Archive::open(zip.as_slice(), OpenFlags(0))
            .map_or(0, |za| za.get_num_entries(Flags::NONE));
        let password = |rng: &mut Rng| -> String {
            match rng.below(5) {
                0 => "-".into(),
                1 | 2 if !passwords.is_empty() => {
                    hex(&passwords[rng.below(passwords.len() as u64) as usize])
                }
                _ => hex(rng.pick(PASSWORDS)),
            }
        };
        let mut ops = Vec::new();
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(n + 1);
            ops.push(match rng.below(9) {
                0..=2 => {
                    let method = rng.pick(&[0, 1, 257, 258, 259]);
                    format!("y{i}:{method}:{}", password(rng))
                }
                3 => format!("P{}", password(rng)),
                4 => format!(
                    "z{i}:{}:{}",
                    rng.pick(&[0, 8, -1, 12, 14, 93, 95]),
                    rng.below(10)
                ),
                5 => format!("m{i}:{}", 1_000_000_000 + rng.below(500_000_000)),
                6 => format!("u{i}"),
                7 => format!("R{i}:{}:{}:s", new_mtime(rng), hex(&new_data(rng))),
                _ => format!("c{i}:{}:0", hex(b"note")),
            });
        }
        let ops = ops.join(",");
        requests.push(match rng.below(3) {
            0 => format!("edit 0 {ops} {}", hex(&zip)),
            _ => format!("editb 0 {} {ops} {}", rng.pick(&[0, 0, 100]), hex(&zip)),
        });
    }
    requests
}

/// `count` decrypt requests on archives libzip encrypted, some damaged:
/// with each way of giving the password, the right one, wrong ones, none,
/// and one cut at its NUL byte.
fn decrypt_requests(oracle: &mut Oracle, rng: &mut Rng, count: usize, max_len: u64) -> Vec<String> {
    let mut requests = Vec::new();
    while requests.len() < count {
        let Some((mut zip, passwords)) = encrypted_archive(oracle, rng, max_len) else {
            continue;
        };
        if rng.below(4) == 0 {
            zip = damage(rng, &zip);
        }
        for _ in 0..3 {
            let how = rng.pick(&["n", "d", "e", "x", "d", "e"]);
            let password: Vec<u8> = match rng.below(6) {
                0..=2 if !passwords.is_empty() => {
                    passwords[rng.below(passwords.len() as u64) as usize].clone()
                }
                3 => b"wrong".to_vec(),
                4 => Vec::new(),
                _ => rng.pick(PASSWORDS).to_vec(),
            };
            let flags = rng.pick(&[0, 4]);
            let kind = if rng.below(8) == 0 { "f" } else { "b" };
            // 0, ZIP_FL_COMPRESSED, ZIP_FL_ENCRYPTED
            let fflags = rng.pick(&[0, 0, 0, 4, 32]);
            let chunks = rng.pick(&["8192", "1", "7,100", "65536", "3,5000,1"]);
            let limit = match rng.below(6) {
                0 => rng.below(100) as i64,
                _ => -1,
            };
            requests.push(format!(
                "decrypt {flags} {kind} {how} {} {fflags} {chunks} {limit} {}",
                hex(&password),
                hex(&zip)
            ));
        }
    }
    requests
}

/// libzip's test archives, where the libzip sources are fetched.
fn regress_archives() -> Vec<(String, Vec<u8>)> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"));
    let regress = cache.join("libzip-1.12.1-source/libzip-1.12.1/regress");
    let mut files = Vec::new();
    for folder in [regress.clone(), regress.join("data")] {
        let Ok(dir) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in dir {
            let path = entry.unwrap().path();
            if path.is_file() {
                files.push((
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    std::fs::read(&path).unwrap(),
                ));
            }
        }
    }
    files.sort();
    files
}

#[test]
fn regress_archives_match_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let files = regress_archives();
    assert!(
        files.len() > 150,
        "libzip's regress files are missing: {}",
        files.len()
    );
    for (name, data) in &files {
        // The large ones take the oracle's line too long for no gain.
        if data.len() > 1 << 20 {
            continue;
        }
        for flags in [0, 4] {
            for kind in ["b", "f"] {
                let request = format!("open {flags} {kind} {}", hex(data));
                let want = oracle.ask(&request);
                assert_eq!(
                    answer(&request),
                    want,
                    "{name} with flags {flags}, source {kind}"
                );
            }
        }
    }
}

/// ZipDiff's archives (`testdata/zipdiff`), which ZIP parsers read
/// differently, read from the one archive they are kept in.
fn zipdiff_archives() -> Vec<(String, Vec<u8>)> {
    let data = std::fs::read(repository().join("testdata/zipdiff/constructions.zip")).unwrap();
    let za = Archive::open(data.as_slice(), OpenFlags::CHECKCONS).unwrap();
    let archives: Vec<(String, Vec<u8>)> = (0..za.get_num_entries(Flags::NONE))
        .map(|i| {
            let name = za.get_name(i, Flags::NONE).unwrap();
            (
                String::from_utf8_lossy(name).into_owned(),
                entry_data(&za, i).unwrap(),
            )
        })
        .collect();
    assert_eq!(archives.len(), 5927);
    archives
}

/// ZipDiff's archives open, and read, as libzip opens and reads them:
/// where parsers disagree, the port agrees with libzip.
#[test]
fn zipdiff_archives_match_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut compared = 0;
    for (name, data) in &zipdiff_archives() {
        // c3-8, whose 65,536 entries take the oracle's line too long.
        if data.len() > 1 << 20 {
            continue;
        }
        compared += 1;
        for flags in [0, 4] {
            for kind in ["b", "f"] {
                let request = format!("open {flags} {kind} {}", hex(data));
                let want = oracle.ask(&request);
                assert_eq!(
                    answer(&request),
                    want,
                    "{name} with flags {flags}, source {kind}"
                );
            }
        }
        for parameters in ["0 b 0 8192 -1", "4 b 0 8192 -1", "0 f 4 100 -1"] {
            let request = format!("read {parameters} {}", hex(data));
            let want = oracle.ask(&request);
            assert_eq!(answer(&request), want, "{name}: read {parameters}");
        }
    }
    assert_eq!(compared, 5926);
}

#[test]
fn regress_archives_read_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x2400_0001);
    for (name, data) in &regress_archives() {
        if data.len() > 1 << 20 {
            continue;
        }
        for parameters in [
            "0 b 0 8192 -1",
            "4 b 0 8192 -1",
            "0 f 4 100 -1",
            "0 b 0 1 -1",
        ]
        .map(String::from)
        .into_iter()
        .chain([read_parameters(&mut rng)])
        {
            let request = format!("read {parameters} {}", hex(data));
            let want = oracle.ask(&request);
            assert_eq!(answer(&request), want, "{name}: read {parameters}");
        }
    }
}

#[test]
fn regress_archives_read_in_ranges_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x2800_0001);
    for (name, data) in &regress_archives() {
        if data.len() > 1 << 20 {
            continue;
        }
        for parameters in ["0 b 2 3", "4 b 0 -1"]
            .map(String::from)
            .into_iter()
            .chain([range_parameters(&mut rng)])
        {
            let request = format!("range {parameters} {}", hex(data));
            let want = oracle.ask(&request);
            assert_eq!(answer(&request), want, "{name}: range {parameters}");
        }
    }
}

#[test]
fn generated_archives_read_in_ranges_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x2800_0002);
    for request in range_requests(&mut rng, 500) {
        let want = oracle.ask(&request);
        assert_eq!(answer(&request), want, "{request:.400}");
    }
}

#[test]
fn port_reads_ranges_as_recorded() {
    replay(&recorded_range_path(), 200);
}

#[test]
#[ignore = "rewrites testdata/oracle/zip-range.txt from the oracle"]
fn record_range_answers() {
    let mut rng = Rng(0x2800_0003);
    record(
        &recorded_range_path(),
        "Ranges",
        "record_range_answers",
        range_requests(&mut rng, 1500),
        4_000,
        5,
    );
}

#[test]
fn generated_archives_read_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x2400_0002);
    for request in read_requests(&mut rng, 800) {
        let want = oracle.ask(&request);
        assert_eq!(answer(&request), want, "{request:.400}");
    }
}

#[test]
fn encrypted_archives_written_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x4100_0001);
    for request in encrypt_requests(&mut oracle, &mut rng, 800, 9000) {
        let want = oracle.ask(&request);
        assert_edit(&request, &want, &format!("{request:.400}"));
    }
}

#[test]
fn encrypted_archives_read_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x4000_0001);
    for request in decrypt_requests(&mut oracle, &mut rng, 1200, 9000) {
        let want = oracle.ask(&request);
        assert_eq!(answer(&request), want, "{request:.400}");
    }
}

#[test]
fn generated_archives_match_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x2100_0001);
    for request in requests(&mut rng, 1500) {
        let want = oracle.ask(&request);
        assert_eq!(answer(&request), want, "{request:.400}");
    }
}

#[test]
fn generated_archives_edit_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x3000_0001);
    for request in edit_requests(&mut rng, 3000) {
        let want = oracle.ask(&request);
        assert_edit(&request, &want, &format!("{request:.400}"));
    }
}

/// The levels libzip can reach, on more data than a block holds: to 22, those
/// past it and the negative ones, which libzip's `u16` of flags puts past it
/// too and leaves to libzstd, and those that wrap around into the range.
#[test]
fn zstd_entries_written_like_libzip_at_every_level() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x3000_0093);
    let data = hex(&text(&mut rng, 300_000));
    let mut levels = vec![-131_073i32, -131_072, -1000, 23, 65_535, 65_536 + 5];
    levels.extend(-7..=22);
    for level in levels {
        let ops = format!(
            "+{}:0:1000000000:{data}:{},z0:93:{}",
            hex(b"a"),
            rng.pick(&["s", "u"]),
            level as u32
        );
        let request = format!("editb 0 0 {ops} -");
        let want = oracle.ask(&request);
        assert_edit(&request, &want, &format!("level {level}"));
    }
}

#[test]
fn generated_archives_edit_in_buffers_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x3000_0004);
    for request in editb_requests(&mut rng, 2000) {
        let want = oracle.ask(&request);
        assert_edit(&request, &want, &format!("{request:.400}"));
    }
}

#[test]
fn regress_archives_edit_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x3000_0002);
    for (name, data) in &regress_archives() {
        if data.len() > 1 << 20 {
            continue;
        }
        for ops in [
            "-".to_string(),
            "d0".to_string(),
            "a6869".to_string(),
            edit_ops(&mut rng, data),
        ] {
            let request = format!("edit 0 {ops} {}", hex(data));
            let want = oracle.ask(&request);
            assert_edit(&request, &want, &format!("{name}: edit {ops}"));
        }
    }
}

/// An entry stored at 24:14:18 (an MS-DOS hour out of range), compressed
/// again and encrypted with ZipCrypto under the default password: libzip
/// writes the time as it was in the header, but takes the check byte of
/// its encryption header from the time of its stat, put back in range, so
/// that the password it was encrypted with is refused. The port writes the
/// same archive, and refuses the password the same way.
#[test]
fn zipcrypto_check_byte_of_a_time_out_of_range_moves() {
    // "hello" as a.txt, stored, at 24:14:18 on 2003-07-17.
    let archive = concat!(
        "504b0304140000000000c9c1f12f86a61036050000000500000005000000612e74787468656c6c6f",
        "504b01021400140000000000c9c1f12f86a610360500000005000000050000000000000000000000",
        "000000000000612e747874504b0506000000000100010033000000280000000000",
    );
    let data = unhex(archive);
    for method in [-1, 8, 12, 0] {
        let ops = format!("z0:{method}:8,y0:1:-,P666f6f");
        let request = format!("edit 0 {ops} {archive}");
        if let Some(mut oracle) = Oracle::spawn() {
            let want = oracle.ask(&request);
            assert_edit(&request, &want, &request);
        }
        let mut za = Archive::open(data.as_slice(), OpenFlags(0)).unwrap();
        assert_eq!(
            za.file_get_dos_time(0, Flags::NONE).unwrap(),
            (0xc1c9, 0x2ff1)
        );
        za.set_file_compression(0, method, 8).unwrap();
        za.file_set_encryption(0, hivepack::zip::em::TRAD_PKWARE, None)
            .unwrap();
        za.set_default_password(Some(b"foo"));
        za.set_random_source(Some(oracle_random(&ops)));
        let mut out = std::io::Cursor::new(Vec::new());
        assert_eq!(za.close_to(&mut out).unwrap(), Closed::Written);
        let new = Archive::open(out.get_ref().as_slice(), OpenFlags(0)).unwrap();
        assert_eq!(
            new.file_get_dos_time(0, Flags::NONE).unwrap(),
            (0xc1c9, 0x2ff1)
        );
        let read = new.fopen_index_encrypted(0, Flags::NONE, Some(b"foo"));
        // Stored, the entry is not compressed again, and reads.
        assert_eq!(read.is_ok(), method == 0, "method {method}");
    }
}

/// An archive of `count` empty stored files, with the Zip64 end of central
/// directory record when the count needs it.
fn many_entries(count: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for i in 0..count {
        let name = format!("f{i}");
        let offset = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        for v in [10, 0, 0, 0, 0x21] {
            put16(&mut out, v);
        }
        for _ in 0..3 {
            put32(&mut out, 0);
        }
        put16(&mut out, name.len() as u16);
        put16(&mut out, 0);
        out.extend_from_slice(name.as_bytes());

        central.extend_from_slice(b"PK\x01\x02");
        for v in [0x031e, 10, 0, 0, 0, 0x21] {
            put16(&mut central, v);
        }
        for _ in 0..3 {
            put32(&mut central, 0);
        }
        for v in [name.len() as u16, 0, 0, 0, 0] {
            put16(&mut central, v);
        }
        put32(&mut central, 0);
        put32(&mut central, offset);
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u64;
    let cd_size = central.len() as u64;
    out.extend_from_slice(&central);
    if count > 0xffff {
        let eocd64_offset = out.len() as u64;
        out.extend_from_slice(b"PK\x06\x06");
        put64(&mut out, 44);
        put16(&mut out, 45);
        put16(&mut out, 45);
        put32(&mut out, 0);
        put32(&mut out, 0);
        put64(&mut out, u64::from(count));
        put64(&mut out, u64::from(count));
        put64(&mut out, cd_size);
        put64(&mut out, cd_offset);
        out.extend_from_slice(b"PK\x06\x07");
        put32(&mut out, 0);
        put64(&mut out, eocd64_offset);
        put32(&mut out, 1);
    }
    out.extend_from_slice(b"PK\x05\x06");
    put32(&mut out, 0);
    put16(&mut out, count.min(0xffff) as u16);
    put16(&mut out, count.min(0xffff) as u16);
    put32(&mut out, cd_size as u32);
    put32(&mut out, cd_offset as u32);
    put16(&mut out, 0);
    out
}

/// More than 65,535 entries take the Zip64 end of central directory
/// records, and 65,535 exactly do not, but fill the count fields.
#[test]
fn many_entries_edit_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let zip = hex(&many_entries(0x1_0003));
    for ops in ["d7", "d0,d1,d2,d3", "d0,d1,d2,d3,d4", "a6869,r5:6e6577:0"] {
        let request = format!("edit 0 {ops} {zip}");
        let want = oracle.ask(&request);
        assert!(want.contains("|written 504b"), "{:.200}", want);
        assert_edit(&request, &want, &format!("edit {ops}"));
    }
}

/// Two deflated entries of 10 bytes whose Zip64 fields libzip writes
/// short: "a", whose size is exactly 0xffffffff, and "b", larger, on disk
/// 0xffff.
fn zip64_edge_archive() -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, size, disk) in [(b'a', 0xffff_ffff_u64, 0u32), (b'b', 0x1_0000_0000, 0xffff)] {
        let offset = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        for v in [45, 0, 8, 0, 0x21] {
            put16(&mut out, v);
        }
        put32(&mut out, 0);
        put32(&mut out, 10);
        put32(&mut out, 0xffff_ffff);
        put16(&mut out, 1);
        put16(&mut out, 20);
        out.push(name);
        put16(&mut out, 1);
        put16(&mut out, 16);
        put64(&mut out, size);
        put64(&mut out, 10);
        out.extend_from_slice(&[0x55; 10]);

        central.extend_from_slice(b"PK\x01\x02");
        for v in [0x031e, 45, 0, 8, 0, 0x21] {
            put16(&mut central, v);
        }
        put32(&mut central, 0);
        put32(&mut central, 10);
        put32(&mut central, 0xffff_ffff);
        let ef_len = if disk == 0 { 12 } else { 16 };
        for v in [1, ef_len, 0, disk as u16, 0] {
            put16(&mut central, v);
        }
        put32(&mut central, 0);
        put32(&mut central, offset);
        central.push(name);
        put16(&mut central, 1);
        put16(&mut central, ef_len - 4);
        put64(&mut central, size);
        if disk != 0 {
            put32(&mut central, disk);
        }
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    for v in [0, 0, 2, 2] {
        put16(&mut out, v);
    }
    put32(&mut out, central.len() as u32);
    put32(&mut out, cd_offset);
    put16(&mut out, 0);
    out
}

/// Differs from libzip, which writes these Zip64 fields without the value
/// and then refuses the archive: the port writes one that reads back.
#[test]
fn zip64_edge_values_read_back() {
    let zip = zip64_edge_archive();
    let mut za = Archive::open(zip.as_slice(), OpenFlags(0)).unwrap();
    za.set_archive_comment(b"hi").unwrap();
    let mut out = std::io::Cursor::new(Vec::new());
    let expected = archive_state(&za, "-");
    assert_eq!(za.close_to(&mut out).unwrap(), Closed::Written);
    check_written(&expected, out.get_ref());
    let written = Archive::open(out.get_ref().as_slice(), OpenFlags(0)).unwrap();
    assert_eq!(
        written.stat_index(0, Flags::NONE).unwrap().size,
        0xffff_ffff
    );
    assert_eq!(
        written.stat_index(1, Flags::NONE).unwrap().size,
        0x1_0000_0000
    );

    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let request = format!("edit 0 a6869 {}", hex(&zip));
    let want = oracle.ask(&request);
    assert!(writes_invalid_zip64(&want), "{want:.300}");
    assert_edit(&request, &want, "a6869");
}

#[test]
fn port_edits_as_recorded() {
    replay(&recorded_edit_path(), 500);
}

#[test]
#[ignore = "rewrites testdata/oracle/zip-edit.txt from the oracle"]
fn record_edit_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x3000_0003);
    // Not those where the port writes differently, or reads Deflate64 or
    // PPMd where libzip refuses them, as the recorded answer may be a hash.
    let mut requests = edit_requests(&mut rng, 700);
    requests.extend(editb_requests(&mut rng, 400));
    let requests = requests
        .into_iter()
        .filter(|request| {
            let want = oracle.ask(request);
            !writes_invalid_zip64(&want)
                && !(want.ends_with(" |e16/0") && has_method_libzip_lacks(request))
        })
        .collect();
    record(
        &recorded_edit_path(),
        "Edits",
        "record_edit_answers",
        requests,
        2_500,
        5,
    );
}

/// The port's answer, or the oracle's on the same system, as it is on
/// Linux, the form the answers are recorded in: `zip_file_set_mtime` fails
/// with the platform's `EOVERFLOW`, which is 75 there.
fn as_on_linux(answer: String) -> String {
    let empty: &[u8] = &[];
    let mut za = Archive::open(empty, OpenFlags(0)).unwrap();
    let eoverflow = za
        .file_set_mtime(0, i64::MAX, Flags::NONE)
        .unwrap_err()
        .system();
    if eoverflow == 75 {
        return answer;
    }
    answer.replace(&format!("e18/{eoverflow}"), "e18/75")
}

/// Replays the answers recorded in `path`.
fn replay(path: &PathBuf, at_least: usize) {
    let text = std::fs::read_to_string(path).expect("the recorded answers");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(
            recorded_form(&as_on_linux(answer(request))),
            want,
            "{request:.300}"
        );
        checked += 1;
    }
    assert!(checked > at_least, "only {checked} recorded answers");
}

/// Writes libzip's answers to `requests` into `path`, but for the long
/// ones (past `max_len`), and, with `errors_kept` n, only every nth archive
/// libzip refuses or finds empty.
fn record(
    path: &PathBuf,
    what: &str,
    test: &str,
    requests: Vec<String>,
    max_len: usize,
    errors_kept: usize,
) {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut text = format!(
        "# {what} from libzip 1.12.1 (tools/zip-oracle), replayed by crates/zip/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test zip_oracle {test} -- --ignored\n"
    );
    let mut refused = 0;
    for request in requests {
        if request.len() > max_len {
            continue;
        }
        let reply = oracle.ask(&request);
        if !reply.contains(" |") {
            refused += 1;
            if refused % errors_kept != 0 {
                continue;
            }
        }
        let _ = writeln!(text, "{request}\t{}", recorded_form(&as_on_linux(reply)));
    }
    std::fs::write(path, text).expect("written");
}

#[test]
fn port_reads_as_recorded() {
    replay(&recorded_read_path(), 300);
}

#[test]
#[ignore = "rewrites testdata/oracle/zip-read.txt from the oracle"]
fn record_read_answers() {
    let mut rng = Rng(0x2400_0003);
    record(
        &recorded_read_path(),
        "Reads",
        "record_read_answers",
        read_requests(&mut rng, 2500),
        5_000,
        5,
    );
}

#[test]
fn port_encrypts_as_recorded() {
    replay(&recorded_encrypt_path(), 250);
}

#[test]
#[ignore = "rewrites testdata/oracle/zip-encrypt.txt from the oracle"]
fn record_encrypt_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x4100_0002);
    let requests = encrypt_requests(&mut oracle, &mut rng, 400, 300);
    record(
        &recorded_encrypt_path(),
        "Encryption",
        "record_encrypt_answers",
        requests,
        8_000,
        5,
    );
}

#[test]
fn port_decrypts_as_recorded() {
    replay(&recorded_decrypt_path(), 300);
}

#[test]
#[ignore = "rewrites testdata/oracle/zip-decrypt.txt from the oracle"]
fn record_decrypt_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x4000_0002);
    let requests = decrypt_requests(&mut oracle, &mut rng, 450, 300);
    record(
        &recorded_decrypt_path(),
        "Decryption",
        "record_decrypt_answers",
        requests,
        6_000,
        5,
    );
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/zip-open.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 500, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/zip-open.txt from the oracle"]
fn record_open_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x2100_0002);
    let mut text = String::from(
        "# Answers from libzip 1.12.1 (tools/zip-oracle), replayed by crates/zip/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test zip_oracle record_open_answers -- --ignored\n",
    );
    for request in requests(&mut rng, 800) {
        if request.len() > 4_000 {
            continue;
        }
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::write(recorded_path(), text).expect("written");
}

/// A sanity check of the harness: libzip's test for an archive with bytes
/// after the end of central directory record (`open_cons_extrabytes.test`).
#[test]
fn refuses_extra_bytes_with_checkcons() {
    let mut zip = Vec::new();
    zip.extend_from_slice(b"PK\x05\x06");
    zip.extend_from_slice(&[0; 18]);
    zip.extend_from_slice(b"junk");
    assert_eq!(answer(&format!("open 4 b {}", hex(&zip))), "e21/2");
    assert_eq!(answer(&format!("open 0 b {}", hex(&zip))), "ok 0 0 - -");
}
